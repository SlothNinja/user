package user

import (
	"crypto/md5"
	"crypto/sha1"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/SlothNinja/log"
	"github.com/SlothNinja/sn"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type User struct {
	c *gin.Context
	// isAdmin bool
	Key *datastore.Key `datastore:"__key__"`
	// ID      int64          `gae:"$id"`
	// Parent  *datastore.Key `gae:"$parent"`
	Data
}

type Data struct {
	Name               string    `json:"name" form:"name"`
	LCName             string    `json:"lcname"`
	Email              string    `json:"email" form:"email"`
	GoogleID           string    `json:"googleid"`
	XMPPNotifications  bool      `json:"xmppnotifications"`
	EmailNotifications bool      `json:"emailnotifications" form:"emailNotifications"`
	EmailReminders     bool      `json:"emailreminders"`
	Admin              bool      `json:"admin"`
	Joined             time.Time `json:"joined"`
	CreatedAt          time.Time `json:"createdat"`
	UpdatedAt          time.Time `json:"updatedat"`
}

func (u *User) Load(ps []datastore.Property) error {
	return datastore.LoadStruct(u, ps)
}

func (u *User) Save() ([]datastore.Property, error) {
	t := time.Now()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = t
	}
	u.UpdatedAt = t
	return datastore.SaveStruct(u)
}

func (u *User) LoadKey(k *datastore.Key) error {
	u.Key = k
	return nil
}

const (
	kind             = "User"
	uidParam         = "uid"
	guserKey         = "guser"
	currentKey       = "current"
	userKey          = "User"
	countKey         = "count"
	homePath         = "/"
	salt             = "slothninja"
	usersKey         = "Users"
	NotFound   int64 = -1
)

type Users []*User

type UserName struct {
	GoogleID string
}

var (
	ErrNotFound     = errors.New("User not found.")
	ErrTooManyFound = errors.New("Found too many users.")
)

func (u *User) CTX() *gin.Context {
	return u.c
}

func RootKey(c *gin.Context) *datastore.Key {
	return datastore.NameKey("Users", "root", nil)
}

func NewKey(c *gin.Context, id int64) *datastore.Key {
	return datastore.IDKey(kind, id, RootKey(c))
}

func New(c *gin.Context, id int64) *User {
	return &User{
		c:   c,
		Key: NewKey(c, id),
		// Parent: RootKey(c),
	}
}

func (u User) ID() int64 {
	if u.Key == nil {
		return 0
	}
	return u.Key.ID
}

type NUser struct {
	Key *datastore.Key `datastore:"__key__"`
	// ID     string         `gae:"$id"`
	// Parent *datastore.Key `gae:"$parent"`
	// Kind   string         `gae:"$kind"`
	OldID int64 `json:"oldid"`
	Data
}

func (nu NUser) ID() string {
	if nu.Key == nil {
		return ""
	}
	return nu.Key.Name
}

func NNew(c *gin.Context, id string) *NUser {
	return &NUser{Key: datastore.NameKey(kind, id, RootKey(c))}
	// return &NUser{Parent: RootKey(c), Kind: kind}
}

func ToNUser(c *gin.Context, u *User) (nu *NUser) {
	nu = NNew(c, GenID(u.GoogleID))
	// nu.ID = GenID(u.GoogleID)
	nu.OldID = u.ID()
	nu.Data = u.Data
	return
}

func GenID(gid string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(salt+gid)))
}

func NewKeyFor(c *gin.Context, id int64) *datastore.Key {
	u := New(c, id)
	return u.Key
	// u.ID = id
	// return datastore.KeyForObj(c, u)
}

// func FromGUser(c *gin.Context, gu *user.User) *User {
// 	if gu == nil {
// 		return nil
// 	} else {
// 		n := strings.Split(gu.Email, "@")[0]
// 		u := New(c, 0)
// 		u.Name = n
// 		u.LCName = strings.ToLower(n)
// 		u.Email = gu.Email
// 		u.GoogleID = gu.ID
// 		return u
// 	}
// }

//func ByGoogleID(c *gin.Context, gid string) (*User, error) {
//	q := datastore.NewQuery(kind).Ancestor(RootKey(c)).Eq("GoogleID", gid).KeysOnly(true)
//
//	var keys []*datastore.Key
//	err := datastore.GetAll(c, q, &keys)
//	if err != nil {
//		return nil, err
//	}
//
//	u := New(c)
//	//var key *datastore.Key
//	switch l := len(keys); l {
//	case 0:
//		return nil, ErrNotFound
//	case 1:
//		datastore.PopulateKey(u, keys[0])
//		if err = datastore.Get(c, u); err != nil {
//			return nil, err
//		}
//	default:
//		return nil, ErrTooManyFound
//	}
//
//	return u, nil
//}

func ByGoogleID(c *gin.Context, gid string) (nu *NUser, err error) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	u := New(c, 0)
	u.GoogleID = gid
	nu = ToNUser(c, u)
	log.Debugf("nu: %#v", nu)

	dsClient, err := datastore.NewClient(c, "")
	if err != nil {
		return nil, err
	}

	if err = dsClient.Get(c, nu.Key, nu); err != nil {
		if err == datastore.ErrNoSuchEntity {
			err = ErrNotFound
		}
		log.Warningf(err.Error())
		return
	}

	return
}

//func GetMulti(c *gin.Context, ks []*datastore.Key) (Users, error) {
//	us := make([]*User, len(ks))
//	for i, k := range ks {
//		us[i] = new(User)
//		datastore.PopulateKey(us[i], k)
//	}
//	err := datastore.Get(c, us)
//	return us, err
//}
//
//func ByID(c *gin.Context, id int64) (u *User, err error) {
//	u = New(c)
//	u.ID = id
//	err = datastore.Get(c, u)
//	return
//}
//
//func BySID(c *gin.Context, sid string) (*User, error) {
//	id, err := strconv.ParseInt(sid, 10, 64)
//	if err != nil {
//		return nil, err
//	}
//	return ByID(c, id)
//}
//
//func ByIDS(c *gin.Context, ids []int64) (Users, error) {
//	ks := make([]*datastore.Key, len(ids))
//	for i, id := range ids {
//		ks[i] = NewKey(c, id)
//	}
//	return GetMulti(c, ks)
//}

func AllQuery(c *gin.Context) *datastore.Query {
	return datastore.NewQuery(kind).Ancestor(RootKey(c))
}

//func getByGoogleID(c *gin.Context, gid string) (*User, error) {
//	itm := memcache.NewItem(c, MCKey(c, gid))
//	if err := memcache.Get(c, itm); err != nil {
//		return nil, err
//	}
//
//	u := New(c)
//	if err := decode(u, itm.Value()); err != nil {
//		return nil, err
//	}
//	return u, nil
//}

//func (u User) encode() ([]byte, error) {
//	return codec.Encode(u)
//}
//
//func decode(dst *User, v []byte) error {
//	return codec.Decode(dst, v)
//}
//
func MCKey(c *gin.Context, gid string) string {
	return sn.VersionID() + gid
}

//func setByGoogleID(c *gin.Context, gid string, u *User) error {
//	if v, err := u.encode(); err != nil {
//		return err
//	} else {
//		c := restful.ContextFrom(c)
//		return memcache.Set(c, memcache.NewItem(c, MCKey(c, gid)).SetValue(v))
//	}
//}

func IsAdmin(c *gin.Context) bool {
	cu := CurrentFrom(c)
	return cu != nil && cu.Admin
}

func (u *User) IsAdmin() bool {
	return u != nil && u.Admin
}

func (u *User) IsAdminOrCurrent(c *gin.Context) bool {
	return IsAdmin(c) || u.IsCurrent(c)
}

func (u *User) Gravatar(options ...string) template.URL {
	return template.URL(GravatarURL(u.Email, options...))
}

func (u *NUser) Gravatar(options ...string) template.URL {
	return template.URL(GravatarURL(u.Email, options...))
}

func GravatarURL(email string, options ...string) string {
	size := "80"
	if len(options) == 1 {
		size = options[0]
	}

	email = strings.ToLower(strings.TrimSpace(email))
	hash := md5.New()
	hash.Write([]byte(email))
	md5string := fmt.Sprintf("%x", hash.Sum(nil))
	return fmt.Sprintf("http://www.gravatar.com/avatar/%s?s=%s&d=monsterid", md5string, size)
}

func (u *User) Update(c *gin.Context) error {
	obj := struct {
		Name               string `form:"name"`
		Email              string `form:"email"`
		EmailNotifications bool   `form:"emailNotifications"`
	}{}

	err := c.ShouldBind(&obj)
	if err != nil {
		return err
	}

	log.Debugf("obj: %#v", obj)

	//n := New(c, 0)
	// 	if err := restful.BindWith(c, n, binding.FormPost); err != nil {
	// 		return err
	// 	}

	// log.Debugf("n: %#v", n)

	if IsAdmin(c) {
		if obj.Email != "" {
			u.Email = obj.Email
		}
	}

	if u.IsAdminOrCurrent(c) {
		if err := u.updateName(c, obj.Name); err != nil {
			return err
		}
		u.EmailNotifications = obj.EmailNotifications
	}

	return nil
}

func (u *User) updateName(c *gin.Context, n string) error {
	matcher := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._%+\-]+$`)

	switch {
	case n == u.Name:
		return nil
	case len(n) > 15:
		return fmt.Errorf("%q is too long.", n)
	case !matcher.MatchString(n):
		return fmt.Errorf("%q is not a valid user name.", n)
	default:
		uniq, err := NameIsUnique(c, n)
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

func NameIsUnique(c *gin.Context, name string) (bool, error) {
	LCName := strings.ToLower(name)

	dsClient, err := datastore.NewClient(c, "")
	if err != nil {
		return false, err
	}

	q := datastore.NewQuery("User").Filter("LCName=", LCName)

	cnt, err := dsClient.Count(c, q)
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
	return template.HTML(fmt.Sprintf("/user/show/%d", uid))
}

// func GetGUserHandler(c *gin.Context) {
// 	log.Debugf("Entering")
// 	defer log.Debugf("Exiting")
//
// 	WithGUser(c, user.Current(c))
// }

// Use after GetGUserHandler handler
// func GetCUserHandler(c *gin.Context) {
// 	log.Debugf("Entering")
// 	defer log.Debugf("Exiting")
//
// 	var u *User
// 	if gu := GUserFrom(c); gu != nil {
// 		// Attempt to fetch and return stored User
// 		if nu, err := ByGoogleID(c, gu.ID); err != nil {
// 			log.Debugf(err.Error())
// 		} else {
// 			u = New(c, nu.OldID)
// 			u.Data, u.isAdmin = nu.Data, user.IsAdmin(c)
// 			// u.ID, u.Data, u.isAdmin = nu.OldID, nu.Data, user.IsAdmin(c)
// 		}
// 	}
// 	WithCurrent(c, u)
// }

func GetCUserHandler(c *gin.Context) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	session := sessions.Default(c)
	token, ok := SessionTokenFrom(session)
	if !ok {
		log.Warningf("missing token")
		return
	}

	if token.Loaded {
		u := New(c, token.ID())
		u.Data = token.User.Data
		WithCurrent(c, u)
		return
	}

	dsClient, err := datastore.NewClient(c, "")
	if err != nil {
		log.Warningf("Client error: %v", err)
		return
	}

	u := New(c, token.ID())
	err = dsClient.Get(c, u.Key, u)
	if err != nil {
		log.Warningf(err.Error())
		return
	}
	log.Debugf("u: %#v", u)
	WithCurrent(c, u)
}

// Use after GetGUserHandler and GetUserHandler handlers
// func RequireLogin() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		if gu := GUserFrom(c); gu == nil {
// 			log.Warningf("RequireLogin failed.")
// 			c.Redirect(http.StatusSeeOther, "/")
// 			c.Abort()
// 		}
// 	}
// }

func RequireCurrentUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		if cu := CurrentFrom(c); cu == nil {
			log.Warningf("RequireCurrentUser failed.")
			c.Redirect(http.StatusSeeOther, "/")
			c.Abort()
		}
	}
}

func RequireAdmin(c *gin.Context) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	if !IsAdmin(c) {
		log.Warningf("user not admin.")
		c.Redirect(http.StatusSeeOther, "/")
		c.Abort()
	}
}

func Fetch(c *gin.Context) {
	log.Debugf("Entering user#Fetch")
	defer log.Debugf("Exiting user#Fetch")

	uid, err := getUID(c)
	if err != nil || uid == NotFound {
		log.Errorf("getUID error: %v", err.Error())
		c.Redirect(http.StatusSeeOther, "/")
		c.Abort()
		return
	}

	u := New(c, uid)
	// u.ID = uid
	dsClient, err := datastore.NewClient(c, "")
	if err != nil {
		log.Errorf(err.Error())
		c.Redirect(http.StatusSeeOther, "/")
		c.Abort()
		return
	}

	if err = dsClient.Get(c, u.Key, u); err != nil {
		log.Errorf("Unable to get user for id: %v", c.Param("uid"))
		c.Redirect(http.StatusSeeOther, "/")
		c.Abort()
	} else {
		WithUser(c, u)
	}
}

func FetchAll(c *gin.Context) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	us, cnt, err := getFiltered(c, c.PostForm("start"), c.PostForm("length"))

	if err != nil {
		log.Errorf(err.Error())
		c.Redirect(http.StatusSeeOther, homePath)
		c.Abort()
	}
	withUsers(withCount(c, cnt), us)
}

func getFiltered(c *gin.Context, start, length string) (us []interface{}, cnt int64, err error) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	dsClient, err := datastore.NewClient(c, "")
	if err != nil {
		return nil, 0, err
	}

	q := AllQuery(c).Order("GoogleID").KeysOnly()
	icnt, err := dsClient.Count(c, q)
	if err != nil {
		return
	}
	cnt = int64(icnt)

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

	ks, err := dsClient.GetAll(c, q, nil)
	if err != nil {
		return
	}

	l := len(ks)
	us = make([]interface{}, l)
	for i := range us {
		if id := ks[i].ID; id != 0 {
			u := New(c, id)
			// u.ID = id
			us[i] = u
		} else {
			u := NNew(c, ks[i].Name)
			// u.ID = ks[i].StringID()
			us[i] = u
		}
	}

	err = dsClient.GetMulti(c, ks, us)
	return
}

//func FetchAll(c *gin.Context) {
//	log.Debugf("Entering user#Fetch")
//	defer log.Debugf("Exiting user#Fetch")
//
//	var (
//		ks  []*datastore.Key
//		err error
//	)
//
//	if err = datastore.GetAll(c, q, &ks); err != nil {
//		log.Errorf("unable to get users, error %v", err.Error())
//		c.Redirect(http.StatusSeeOther, "/")
//		c.Abort()
//	}
//
//	u := New(c)
//	u.ID = uid
//	if err = datastore.Get(c, u); err != nil {
//		log.Errorf("Unable to get user for id: %v", c.Param("uid"))
//		c.Redirect(http.StatusSeeOther, "/")
//		c.Abort()
//	} else {
//		WithUser(c, u)
//	}
//}

func getUID(c *gin.Context) (id int64, err error) {
	if id, err = strconv.ParseInt(c.Param(uidParam), 10, 64); err != nil {
		id = NotFound
	}
	return
}

func Fetched(c *gin.Context) *User {
	return From(c)
}

func Gravatar(u *User) template.HTML {
	return template.HTML(fmt.Sprintf(`<a href="/user/show/%d"><img src=%q alt="Gravatar" class="black-border" /></a>`, u.ID, u.Gravatar()))
}

func NGravatar(nu *NUser) template.HTML {
	return template.HTML(fmt.Sprintf(`<a href="/user/show/%s"><img src=%q alt="Gravatar" class="black-border" /></a>`, nu.ID(), nu.Gravatar()))
}

func from(c *gin.Context, key string) (u *User) {
	u, _ = c.Value(key).(*User)
	return
}

func From(c *gin.Context) *User {
	return from(c, userKey)
}

func CurrentFrom(c *gin.Context) *User {
	return from(c, currentKey)
}

func (u *User) IsCurrent(c *gin.Context) bool {
	return u.Equal(CurrentFrom(c))
}

// func GUserFrom(c *gin.Context) (u *user.User) {
// 	log.Debugf("Entering")
// 	defer log.Debugf("Exiting")
//
// 	u, _ = c.Value(guserKey).(*user.User)
// 	log.Debugf("u: %#v", u)
// 	return
// }

func WithUser(c *gin.Context, u *User) {
	c.Set(userKey, u)
}

// func WithGUser(c *gin.Context, u *user.User) {
// 	c.Set(guserKey, u)
// }

func WithCurrent(c *gin.Context, u *User) {
	c.Set(currentKey, u)
}

func UsersFrom(c *gin.Context) (us []interface{}) {
	us, _ = c.Value(usersKey).([]interface{})
	return
}

func withUsers(c *gin.Context, us []interface{}) {
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
