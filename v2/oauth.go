package user

import (
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
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
	gob.Register(new(sessionToken))
}

func Login(path string) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debugf("Entering")
		defer log.Debugf("Exiting")

		session := sessions.Default(c)
		state := randToken(tokenLength)
		session.Set(stateKey, state)
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

	return &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
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

func (client Client) Auth(path string) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debugf("Entering")
		defer log.Debugf("Exiting")

		uInfo, err := getUInfo(c, path)
		if err != nil {
			log.Errorf(err.Error())
			c.Redirect(http.StatusSeeOther, homePath)
			return
		}

		log.Debugf("uInfo: %#v\nerr: %v", uInfo, err)
		oaid := GenOAuthID(uInfo.Sub)
		oa, err := client.getOAuth(c, oaid)
		log.Debugf("oa: %#v\nerr: %v", oa, err)
		// Succesfully pulled oauth id from datastore
		if err == nil {
			u := New(oa.ID)
			err = client.DS.Get(c, u.Key, u)
			if err != nil {
				log.Errorf(err.Error())
				c.Redirect(http.StatusSeeOther, homePath)
				return
			}

			st := NewSessionToken(u, uInfo.Sub, true)
			saveToSessionAndReturnTo(c, st, homePath)
			return
		}

		// Datastore error other than missing entity.
		if err != datastore.ErrNoSuchEntity {
			log.Errorf("unable to get user for %#v", uInfo)
			c.Redirect(http.StatusSeeOther, homePath)
			return
		}

		// oauth id not present in datastore
		// Check to see if other entities exist for same email address.
		// If so, use old entities for user
		u, err := client.getByEmail(c, uInfo.Email)
		if err == nil {
			oa := NewOAuth(oaid)
			oa.ID = u.ID()
			_, err = client.DS.Put(c, oa.Key, &oa)
			if err != nil {
				log.Errorf(err.Error())
				c.Redirect(http.StatusSeeOther, homePath)
				return
			}
			st := NewSessionToken(u, uInfo.Sub, true)
			saveToSessionAndReturnTo(c, st, homePath)
			return
		}

		u = New(0)
		u.Name = strings.Split(uInfo.Email, "@")[0]
		u.Email = uInfo.Email
		st := NewSessionToken(u, uInfo.Sub, false)
		saveToSessionAndReturnTo(c, st, userNewPath)
		return
	}
}

func (client Client) As(c *gin.Context) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	uid, err := strconv.ParseInt(c.Param("uid"), 10, 64)
	if err != nil {
		log.Errorf(err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	u := New(uid)
	err = client.DS.Get(c, u.Key, u)
	if err != nil {
		log.Errorf(err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	st := NewSessionToken(u, "", true)
	saveToSessionAndReturnTo(c, st, homePath)
	return
}

func getUInfo(c *gin.Context, path string) (Info, error) {
	// Handle the exchange code to initiate a transport.
	session := sessions.Default(c)
	retrievedState, ok := session.Get(stateKey).(string)
	if !ok || (retrievedState != c.Query(stateKey)) {
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

func (client Client) getOAuth(c *gin.Context, id string) (OAuth, error) {
	u := NewOAuth(id)
	err := client.DS.Get(c, u.Key, &u)
	return u, err
}

func saveToSessionAndReturnTo(c *gin.Context, st *sessionToken, path string) {
	log.Debugf("st: %#v", st)
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

func (client Client) getByEmail(c *gin.Context, email string) (*User, error) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	email = strings.ToLower(strings.TrimSpace(email))
	q := datastore.NewQuery(uKind).
		Ancestor(rootKey()).
		Filter("Email=", email).
		KeysOnly()

	ks, err := client.DS.GetAll(c, q, nil)
	if err != nil {
		return nil, err
	}

	for i := range ks {
		if ks[i].ID != 0 {
			return client.getByID(c, ks[i].ID)
		}
	}
	return nil, errors.New("unable to find user")
}

func (client Client) getByID(c *gin.Context, id int64) (*User, error) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	u := New(id)
	err := client.DS.Get(c, u.Key, u)
	return u, err
}

type sessionToken struct {
	Key    *datastore.Key
	Sub    string
	Loaded bool
	Data
}

func NewSessionToken(u *User, sub string, loaded bool) *sessionToken {
	return &sessionToken{
		Key:    u.Key,
		Sub:    sub,
		Loaded: loaded,
		Data:   u.Data,
	}
}

func (st *sessionToken) SaveTo(s sessions.Session) error {
	s.Set(sessionKey, st)
	return s.Save()
}

func SessionTokenFrom(s sessions.Session) (*sessionToken, bool) {
	token, ok := s.Get(sessionKey).(*sessionToken)
	return token, ok
}
