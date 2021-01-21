package user

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/SlothNinja/log"
	"github.com/SlothNinja/sn"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
)

type User struct {
	Key *datastore.Key `datastore:"__key__"`
	Data
}

type Data struct {
	Name               string    `json:"name"`
	LCName             string    `json:"lcname"`
	Email              string    `json:"email"`
	EmailHash          string    `json:"emailHash"`
	EmailNotifications bool      `json:"emailNotifications"`
	EmailReminders     bool      `json:"emailReminders"`
	GoogleID           string    `json:"googleid"`
	XMPPNotifications  bool      `json:"xmppnotifications"`
	GravType           string    `json:"gravType"`
	Admin              bool      `json:"admin"`
	Joined             time.Time `json:"joined"`
	CreatedAt          time.Time `json:"createdat"`
	UpdatedAt          time.Time `json:"updatedat"`
}

func EmailHash(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	hash := md5.New()
	_, err := hash.Write([]byte(email))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

type Client struct {
	*sn.Client
}

func NewClient(logger *log.Logger, mcache *cache.Cache) *Client {
	logger.Debugf(msgEnter)
	defer logger.Debugf(msgExit)

	if sn.IsProduction() {
		log.Debugf("production")
		dsClient, err := datastore.NewClient(
			context.Background(),
			os.Getenv(USER_PROJECT_ID),
		)
		if err != nil {
			logger.Panicf("unable to connect to user database: %w", err)
		}
		return &Client{sn.NewClient(dsClient, logger, mcache, nil)}

	}
	log.Debugf("development")
	dsClient, err := datastore.NewClient(
		context.Background(),
		os.Getenv(USER_PROJECT_ID),
		option.WithEndpoint(os.Getenv(DS_USER_HOST)),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithInsecure()),
		option.WithGRPCConnectionPool(50),
	)
	if err != nil {
		logger.Panicf("unable to connect to user database: %w", err)
	}
	return &Client{sn.NewClient(dsClient, logger, mcache, nil)}
}

func (u *User) Load(ps []datastore.Property) error {
	return datastore.LoadStruct(u, ps)
}

func (u *User) Save() ([]datastore.Property, error) {
	t := time.Now()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = t
	}

	if u.Joined.IsZero() {
		u.Joined = t
	}
	u.UpdatedAt = t

	return datastore.SaveStruct(u)
}

func (u *User) LoadKey(k *datastore.Key) error {
	u.Key = k
	return nil
}

func (u *User) IsAdmin() bool {
	return u != nil && u.Admin
}

const (
	kind                  = "User"
	uidParam              = "uid"
	guserKey              = "guser"
	currentKey            = "current"
	userKey               = "User"
	countKey              = "count"
	homePath              = "/"
	salt                  = "slothninja"
	usersKey              = "Users"
	msgEnter              = "Entering"
	msgExit               = "Exiting"
	NotFound        int64 = -1
	USER_PROJECT_ID       = "USER_PROJECT_ID"
	DS_USER_HOST          = "DS_USER_HOST"
)

type Users []*User

type UserName struct {
	GoogleID string
}

var (
	ErrNotFound     = errors.New("User not found.")
	ErrTooManyFound = errors.New("Found too many users.")
)

func RootKey() *datastore.Key {
	return datastore.NameKey("Users", "root", nil)
}

func NewKey(id int64) *datastore.Key {
	return datastore.IDKey(kind, id, RootKey())
}

func New(id int64) *User {
	return &User{
		Key: NewKey(id),
	}
}

func (u User) ID() int64 {
	if u.Key == nil {
		return 0
	}
	return u.Key.ID
}

func GenID(gid string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(salt+gid)))
}

func NewKeyFor(id int64) *datastore.Key {
	u := New(id)
	return u.Key
}

func AllQuery(c *gin.Context) *datastore.Query {
	return datastore.NewQuery(kind).Ancestor(RootKey())
}

func MCKey(c *gin.Context, gid string) string {
	return sn.VersionID() + gid
}

func (u *User) Gravatar(size string) template.URL {
	return template.URL(GravatarURL(u.Email, size, u.GravType))
}

func GravatarURL(email, size, gravType string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	hash := md5.New()
	hash.Write([]byte(email))
	md5string := fmt.Sprintf("%x", hash.Sum(nil))
	if gravType == "" || gravType == "personal" {
		return fmt.Sprintf("https://www.gravatar.com/avatar/%s?s=%s&d=monsterid", md5string, size)
	}
	return fmt.Sprintf("https://www.gravatar.com/avatar/%s?s=%s&d=%s&f=y", md5string, size, gravType)
}

func (client Client) Update(c *gin.Context, cu, u1, u2 *User) error {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgExit)

	if isAdmin(cu) {
		client.Log.Debugf("is admin")
		if u2.Email != "" {
			client.Log.Debugf("updating email")
			u1.Email = u2.Email

			hash, err := EmailHash(u1.Email)
			if err != nil {
				return err
			}
			u1.EmailHash = hash
		}

		err := client.updateName(c, u1, u2.Name)
		if err != nil {
			return err
		}
	}

	if isAdmin(cu) || (cu.ID() == u1.ID()) {
		client.Log.Debugf("is admin or current")
		client.Log.Debugf("updating emailNotifications and gravType")
		u1.EmailReminders = u2.EmailReminders
		u1.EmailNotifications = u2.EmailNotifications
		u1.GravType = u2.GravType
		hash, err := EmailHash(u1.Email)
		if err != nil {
			return err
		}
		u1.EmailHash = hash
	}

	return nil
}

func (client Client) updateName(c *gin.Context, u *User, n string) error {
	matcher := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._%+\-]+$`)

	switch {
	case n == u.Name:
		return nil
	case len(n) > 15:
		return fmt.Errorf("%q is too long.", n)
	case !matcher.MatchString(n):
		return fmt.Errorf("%q is not a valid user name.", n)
	default:
		uniq, err := client.NameIsUnique(c, n)
		if err != nil {
			return err
		}
		if !uniq {
			return fmt.Errorf("%q is not a unique user name.", n)
		}
		u.Name = n
		u.LCName = strings.ToLower(n)
		return nil
	}
}

func (client Client) NameIsUnique(c *gin.Context, name string) (bool, error) {
	LCName := strings.ToLower(name)

	q := datastore.NewQuery("User").Filter("LCName=", LCName)

	cnt, err := client.DS.Count(c, q)
	if err != nil {
		return false, err
	}
	return cnt == 0, nil
}

func (u *User) Equal(u2 *User) bool {
	return u2 != nil && u != nil && u.ID() == u2.ID()
}

func (u *User) Link() template.HTML {
	if u == nil {
		return ""
	}
	return LinkFor(u.ID(), u.Name)
}

func LinkFor(uid int64, name string) template.HTML {
	return template.HTML(fmt.Sprintf("<a href=%q>%s</a>", PathFor(uid), name))
}

func PathFor(uid int64) template.HTML {
	return template.HTML(fmt.Sprintf("%s/#/show/%d", getLoginHost(), uid))
}

// func GetCUserHandler(client *datastore.Client) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		log.Debugf(msgEnter)
// 		defer log.Debugf(msgExit)
//
// 		session := sessions.Default(c)
// 		token, ok := SessionTokenFrom(session)
// 		if !ok {
// 			log.Warningf("missing token")
// 			return
// 		}
//
// 		u := New(token.Key.ID)
// 		u.Data = token.Data
// 		WithCurrent(c, u)
// 	}
// }

// func GetCUserHandler(client *datastore.Client) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		log.Debugf("Entering")
// 		defer log.Debugf("Exiting")
//
// 		session := sessions.Default(c)
// 		token, ok := SessionTokenFrom(session)
// 		if !ok {
// 			log.Warningf("missing token")
// 			return
// 		}
//
// 		if token.Loaded {
// 			u := New(c, token.ID())
// 			u.Data = token.User.Data
// 			WithCurrent(c, u)
// 			return
// 		}
//
// 		u := New(c, token.ID())
// 		err := client.Get(c, u.Key, u)
// 		if err != nil {
// 			log.Warningf(err.Error())
// 			return
// 		}
// 		WithCurrent(c, u)
// 	}
// }

// func RequireCurrentUser() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		_, err := CurrentFrom(c)
// 		if err != nil {
// 			log.Warningf("RequireCurrentUser failed.")
// 			c.Redirect(http.StatusSeeOther, "/")
// 			c.Abort()
// 		}
// 	}
// }
//
// func RequireAdmin(c *gin.Context) {
// 	log.Debugf(msgEnter)
// 	defer log.Debugf(msgExit)
//
// 	if !IsAdmin(c) {
// 		log.Warningf("user not admin.")
// 		c.Redirect(http.StatusSeeOther, "/")
// 		c.Abort()
// 	}
// }

func (client Client) Fetch(c *gin.Context) {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgExit)

	uid, err := getUID(c, uidParam)
	if err != nil || uid == NotFound {
		client.Log.Errorf(err.Error())
		c.Redirect(http.StatusSeeOther, "/")
		c.Abort()
		return
	}

	u, err := client.Get(c, uid)
	if err != nil {
		client.Log.Errorf("Unable to get user for id: %v", c.Param("uid"))
		c.Redirect(http.StatusSeeOther, "/")
		c.Abort()
		return
	}
	WithUser(c, u)
}

func (client Client) FetchAll(c *gin.Context) {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgExit)

	us, cnt, err := client.getFiltered(c, c.PostForm("start"), c.PostForm("length"))

	if err != nil {
		client.Log.Errorf(err.Error())
		c.Redirect(http.StatusSeeOther, homePath)
		c.Abort()
	}
	withUsers(withCount(c, cnt), us)
}

func (client Client) getFiltered(c *gin.Context, start, length string) ([]*User, int64, error) {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgExit)

	q := AllQuery(c).KeysOnly()
	icnt, err := client.DS.Count(c, q)
	if err != nil {
		return nil, 0, err
	}
	cnt := int64(icnt)

	if start != "" {
		if st, err := strconv.ParseInt(start, 10, 32); err == nil {
			q = q.Offset(int(st))
		}
	}

	if length != "" {
		if l, err := strconv.ParseInt(length, 10, 32); err == nil {
			q = q.Limit(int(l))
		}
	}

	ks, err := client.DS.GetAll(c, q, nil)
	if err != nil {
		return nil, 0, err
	}

	var us []*User
	for i := range ks {
		id := ks[i].ID
		if id != 0 {
			us = append(us, New(id))
		}
	}

	err = client.DS.GetMulti(c, ks, us)
	return us, cnt, err
}

func getUID(c *gin.Context, param string) (int64, error) {
	id, err := strconv.ParseInt(c.Param(param), 10, 64)
	if err != nil {
		return NotFound, err
	}
	return id, nil
}

func Fetched(c *gin.Context) *User {
	return From(c)
}

func Gravatar(u *User, size string) template.HTML {
	return template.HTML(fmt.Sprintf(`<a href=%q ><img src=%q alt="Gravatar" class="black-border" /></a>`, PathFor(u.ID()), u.Gravatar(size)))
}

func from(c *gin.Context, key string) (u *User) {
	u, _ = c.Value(key).(*User)
	return
}

func From(c *gin.Context) *User {
	return from(c, userKey)
}

var ErrMissingToken = fmt.Errorf("missing token")

func (client Client) Current(c *gin.Context) (*User, error) {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgExit)

	session := sessions.Default(c)
	token, ok := SessionTokenFrom(session)
	if !ok {
		return nil, ErrMissingToken
	}

	return client.Get(c, token.ID)
}

func WithUser(c *gin.Context, u *User) {
	c.Set(userKey, u)
}

func WithCurrent(c *gin.Context, u *User) {
	c.Set(currentKey, u)
}

func UsersFrom(c *gin.Context) []*User {
	us, _ := c.Value(usersKey).([]*User)
	return us
}

func withUsers(c *gin.Context, us []*User) {
	c.Set(usersKey, us)
}

func withCount(c *gin.Context, cnt int64) *gin.Context {
	c.Set(countKey, cnt)
	return c
}

func CountFrom(c *gin.Context) (cnt int64) {
	cnt, _ = c.Value(countKey).(int64)
	return
}

func (u User) MarshalJSON() ([]byte, error) {
	type usr User
	return json.Marshal(struct {
		usr
		ID int64 `json:"id"`
	}{
		usr: usr(u),
		ID:  u.ID(),
	})
}

func (client Client) ByParam(c *gin.Context, param string) (*User, error) {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgExit)

	uid, err := getUID(c, param)
	if err != nil {
		return nil, err
	}

	return client.Get(c, uid)
}

func (client Client) Get(c *gin.Context, id int64) (*User, error) {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgExit)

	return client.getUserByKey(c, NewKey(id))
}

func (client Client) getUserByKey(c *gin.Context, k *datastore.Key) (*User, error) {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgExit)

	u, found := client.getCachedUser(k)
	if found {
		return u, nil
	}

	u = New(k.ID)
	err := client.DS.Get(c, k, u)
	if err != nil {
		return nil, err
	}
	client.cacheUser(u)
	return u, nil
}

func (client Client) getCachedUser(k *datastore.Key) (*User, bool) {
	if k == nil {
		return nil, false
	}

	data, found := client.Cache.Get(k.Encode())
	if !found {
		return nil, false
	}

	u, ok := data.(*User)
	if !ok {
		return nil, false
	}
	return u, true
}

func (client Client) cacheUser(u *User) {
	if u.Key == nil {
		return
	}
	client.Cache.SetDefault(u.Key.Encode(), u)
}

func (client Client) GetMulti(c *gin.Context, ids []int64) ([]*User, error) {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgExit)

	us := make([]*User, len(ids))
	merr := make(datastore.MultiError, len(ids))
	isNil := true

	for i := range ids {
		us[i], merr[i] = client.getUserByKey(c, NewKey(ids[i]))
		if merr[i] != nil {
			isNil = false
		}
	}
	if !isNil {
		return us, merr
	}
	return us, nil
}

func (client Client) AllocateIDs(c *gin.Context, ks []*datastore.Key) ([]*datastore.Key, error) {
	return client.DS.AllocateIDs(c, ks)
}

func (client Client) Put(c *gin.Context, k *datastore.Key, u *User) (*datastore.Key, error) {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgExit)

	return client.putUserByKey(c, k, u)
}

func (client Client) putUserByKey(c *gin.Context, k *datastore.Key, u *User) (*datastore.Key, error) {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgExit)

	k, err := client.DS.Put(c, k, u)
	if err != nil {
		return nil, err
	}
	client.cacheUser(u)
	return k, nil
}

func (client Client) RunInTransaction(c *gin.Context, f func(*datastore.Transaction) error, opts ...datastore.TransactionOption) (*datastore.Commit, error) {
	return client.DS.RunInTransaction(c, f, opts...)
}
