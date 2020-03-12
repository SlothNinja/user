package user

import (
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/SlothNinja/log"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/gofrs/uuid"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func init() {
	gob.Register(sessionToken{})
}

const (
	HOST        = "HOST"
	authPath    = "/auth"
	sessionKey  = "session"
	userNewPath = "/user/new"
	tokenLength = 32
	uKind       = "User"
	oauthsKind  = "OAuths"
	oauthKind   = "OAuth"
	root        = "root"
)

func Login(path string) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debugf("Entering")
		defer log.Debugf("Exiting")

		session := sessions.Default(c)
		state := randToken(tokenLength)
		session.Set("state", state)
		session.Save()

		c.Redirect(http.StatusSeeOther, getLoginURL(c, path, state))
	}
}

func Logout(c *gin.Context) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	s := sessions.Default(c)
	s.Delete(sessionKey)
	err := s.Save()
	if err != nil {
		log.Warningf("unable to save session: %v", err)
	}
	c.Redirect(http.StatusSeeOther, homePath)
}

func randToken(length int) string {
	key := securecookie.GenerateRandomKey(length)
	// b := make([]byte, 32)
	// rand.Read(b)
	return base64.StdEncoding.EncodeToString(key)
}

func getLoginURL(c *gin.Context, path, state string) string {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	// State can be some kind of random generated hash string.
	// See relevant RFC: http://tools.ietf.org/html/rfc6749#section-10.12
	return oauth2Config(c, path, scopes()...).AuthCodeURL(state)
}

func oauth2Config(c *gin.Context, path string, scopes ...string) *oauth2.Config {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	log.Debugf("request: %#v", c.Request)

	// protocol := "http"
	// if c.Request.TLS != nil {
	// 	protocol = "https"
	// }

	return &oauth2.Config{
		ClientID:     "435340145701-t5o50sjq7hsbilopgreobhvrv30e1tj4.apps.googleusercontent.com",
		ClientSecret: "Fe5f-Ht1V5_GohDEOS_TQOVc",
		Endpoint:     google.Endpoint,
		Scopes:       scopes,
		RedirectURL:  fmt.Sprintf("%s%s", getHost(), path),
	}
}

func scopes() []string {
	return []string{"email", "profile", "openid"}
}

func getHost() string {
	return os.Getenv(HOST)
}

type Info struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Profile       string `json:"profile"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	LoggedIn      bool
	Admin         bool
}

const fqdn = "www.slothninja.com"

var namespaceUUID = uuid.NewV5(uuid.NamespaceDNS, fqdn)

// Generates ID for User from ID obtained from OAuth OpenID Connect
func GenOAuthID(s string) string {
	return uuid.NewV5(namespaceUUID, s).String()
}

type OAuth struct {
	Key       *datastore.Key `datastore:"__key__"`
	ID        int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (o *OAuth) Load(ps []datastore.Property) error {
	return datastore.LoadStruct(o, ps)
}

func (o *OAuth) Save() ([]datastore.Property, error) {
	t := time.Now()
	if o.CreatedAt.IsZero() {
		o.CreatedAt = t
	}
	o.UpdatedAt = t
	return datastore.SaveStruct(o)
}

func (o *OAuth) LoadKey(k *datastore.Key) error {
	o.Key = k
	return nil
}

func pk() *datastore.Key {
	return datastore.NameKey(oauthsKind, root, nil)
}

func NewKeyOAuth(id string) *datastore.Key {
	return datastore.NameKey(oauthKind, id, pk())
}

func NewOAuth(id string) OAuth {
	return OAuth{Key: NewKeyOAuth(id)}
}

func ByEmail(c *gin.Context, email string) (OAuth, error) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	dsClient, err := datastore.NewClient(c, "")
	if err != nil {
		return OAuth{}, err
	}

	q := datastore.NewQuery(oauthKind).
		Ancestor(pk()).
		Filter("Equal=", email)

	var oas []OAuth
	_, err = dsClient.GetAll(c, q, oas)
	if err != nil {
		return OAuth{}, err
	}
	l := len(oas)
	if l != 1 {
		return OAuth{}, fmt.Errorf("found %d, expect 1", l)
	}
	return oas[0], nil
}

func Auth(path string) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debugf("Entering")
		defer log.Debugf("Exiting")

		uInfo, err := getUInfo(c, path)
		if err != nil {
			log.Errorf(err.Error())
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		oaid := GenOAuthID(uInfo.Sub)
		oa, err := getOAuth(c, oaid)
		// Succesfully pulled oauth id from datastore

		u := New(c, oa.ID)
		if err == nil {
			dsClient, err := datastore.NewClient(c, "")
			if err != nil {
				log.Errorf("unable to connect to datastore")
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			err = dsClient.Get(c, u.Key, u)
			if err != nil {
				log.Errorf(err.Error())
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			st := NewSessionToken(u, uInfo.Sub, true)
			saveToSessionAndReturnTo(c, st, homePath)
			return
		}

		// Datastore error other than missing entity.
		if err != datastore.ErrNoSuchEntity {
			log.Errorf("unable to get user for key: %#v", u.Key)
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		// oauth id not present in datastore
		// Check to see if other entities exist for same email address.
		// If so, use old entities for user
		u, err = getByEmail(c, uInfo.Email)
		// if err != nil {
		// 	log.Errorf(err.Error())
		// 	c.AbortWithStatus(http.StatusBadRequest)
		// 	return
		// }

		log.Debugf("getByEmail => u: %v\nerr: %v", u, err)

		// u, err = u.migrateOld(c, ks)
		if err == nil {
			dsClient, err := datastore.NewClient(c, "")
			if err != nil {
				log.Errorf(err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			oa := NewOAuth(oaid)
			oa.ID = u.ID()
			_, err = dsClient.Put(c, oa.Key, &oa)
			if err != nil {
				log.Errorf(err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}
			st := NewSessionToken(u, uInfo.Sub, true)
			saveToSessionAndReturnTo(c, st, homePath)
			return
		}

		u = New(c, 0)
		u.Name = strings.Split(uInfo.Email, "@")[0]
		u.Email = uInfo.Email
		st := NewSessionToken(u, uInfo.Sub, false)
		saveToSessionAndReturnTo(c, st, userNewPath)
		return

		// l := len(ks)
		// switch l {
		// case 0: // If no keys, then no old entities for user
		// 	log.Warningf(
		// 		"creating new user for %q without migratition from prior users",
		// 		uInfo.Email,
		// 	)
		// 	u.Email = uInfo.Email
		// 	saveToSessionAndReturnTo(c, u, userNewPath)
		// 	return
		// case 1:
		// 	log.Infof("attempting to migrate user with key %#v and email %q", ks[0], uInfo.Email)
		// 	migrateOld(c, ks)
		// 	ou := New(0)
		// 	err = dsClient.Get(c, ks[0], ou)
		// 	if err == nil {
		// 		u = u.fromOld1(ou)
		// 		_, err = dsClient.Put(c, u.Key, &u)
		// 		if err == nil {
		// 			log.Infof("successfully migrated user for email %q", uInfo.Email)
		// 			u.Loaded = true
		// 			saveToSessionAndReturnTo(c, u, homePath)
		// 			return
		// 		}
		// 	}
		// 	log.Warningf("unable to load user for key %#v due to error: %s", ks[0], err.Error())
		// 	log.Warningf(
		// 		"initiating creation of new user for %q without migrating from prior user",
		// 		uInfo.Email,
		// 	)
		// 	u.Email = uInfo.Email
		// 	saveToSessionAndReturnTo(c, u, userNewPath)
		// 	return
		// case 2:
		// 	ok := ks[0]
		// 	if ok.Name == "" {
		// 		ok = ks[1]
		// 	}
		// 	log.Infof("attempting to migrate user with key %#v and email %q", ok, uInfo.Email)
		// 	ou := NNew(ok.Name)
		// 	err = dsClient.Get(c, ou.Key, ou)
		// 	if err == nil {
		// 		u = u.fromOld2(ou)
		// 		_, err = dsClient.Put(c, u.Key, &u)
		// 		if err == nil {
		// 			log.Infof("successfully migrated user for email %q", uInfo.Email)
		// 			u.Loaded = true
		// 			saveToSessionAndReturnTo(c, u, homePath)
		// 			return
		// 		}
		// 	}
		// 	log.Warningf("unable to load user for key %#v due to error: %s", ok, err.Error())
		// 	log.Warningf(
		// 		"initiating creation of new user for %q without migrating from prior user",
		// 		uInfo.Email,
		// 	)
		// 	u.Email = uInfo.Email
		// 	saveToSessionAndReturnTo(c, u, userNewPath)
		// 	return
		// default:
		// 	log.Warningf(
		// 		"initiating creation of new user for %q without migrating from prior user",
		// 		uInfo.Email,
		// 	)
		// 	u.Email = uInfo.Email
		// 	saveToSessionAndReturnTo(c, u, userNewPath)
		// 	return
		// }
	}
}

func getUInfo(c *gin.Context, path string) (Info, error) {
	// Handle the exchange code to initiate a transport.
	session := sessions.Default(c)
	retrievedState := session.Get("state")
	if retrievedState != c.Query("state") {
		return Info{}, fmt.Errorf("Invalid session state: %s", retrievedState)
	}

	conf := oauth2Config(c, path, scopes()...)
	tok, err := conf.Exchange(c, c.Query("code"))
	if err != nil {
		return Info{}, fmt.Errorf("tok error: %#v", err)
	}

	client := conf.Client(c, tok)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return Info{}, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Info{}, err
	}

	uInfo := Info{}
	var b binding.BindingBody = binding.JSON
	err = b.BindBody(body, &uInfo)
	if err != nil {
		return Info{}, err
	}
	return uInfo, nil
}

func getOAuth(c *gin.Context, id string) (OAuth, error) {
	u := NewOAuth(id)
	dsClient, err := datastore.NewClient(c, "")
	if err != nil {
		return u, err
	}
	err = dsClient.Get(c, u.Key, &u)
	return u, err
}

func saveToSessionAndReturnTo(c *gin.Context, st sessionToken, path string) {
	session := sessions.Default(c)
	err := st.SaveTo(session)
	if err != nil {
		log.Errorf(err.Error())
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	c.Redirect(http.StatusSeeOther, path)
	return
}

func getByEmail(c *gin.Context, email string) (*User, error) {
	dsClient, err := datastore.NewClient(c, "")
	if err != nil {
		return nil, err
	}

	q := datastore.NewQuery(uKind).
		Ancestor(RootKey(c)).
		Filter("Email=", email).
		KeysOnly()

	ks, err := dsClient.GetAll(c, q, nil)
	if err != nil {
		return nil, err
	}

	log.Debugf("ks: %v", ks)
	for i := range ks {
		if ks[i].ID != 0 {
			return getByID(c, ks[i].ID)
		}
	}
	return nil, errors.New("unable to find user")
}

func getByID(c *gin.Context, id int64) (*User, error) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	dsClient, err := datastore.NewClient(c, "")
	if err != nil {
		return nil, err
	}

	u := New(c, id)
	err = dsClient.Get(c, u.Key, u)
	return u, err
}

type sessionToken struct {
	Sub    string
	Loaded bool
	*User
}

func NewSessionToken(u *User, sub string, loaded bool) sessionToken {
	return sessionToken{
		Sub:    sub,
		Loaded: loaded,
		User:   u,
	}
}

func (st sessionToken) SaveTo(s sessions.Session) error {
	s.Set(sessionKey, st)
	return s.Save()
}

func SessionTokenFrom(s sessions.Session) (sessionToken, bool) {
	token, ok := s.Get(sessionKey).(sessionToken)
	return token, ok
}
