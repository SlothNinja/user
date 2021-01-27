package user

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/SlothNinja/restful"
	"github.com/gin-gonic/gin"
)

const (
	sKind    = "Stats"
	sName    = "root"
	statsKey = "Stats"
)

var (
	ErrMissingUser  = errors.New("missing user")
	ErrInvalidCache = errors.New("invalid cache value")
)

// type Client struct {
// 	*sn.Client
// 	User *user.Client
// }
//
// func NewClient(dsClient *datastore.Client, userClient *user.Client, logger *log.Logger, mcache *cache.Cache) *Client {
// 	return &Client{
// 		Client: sn.NewClient(dsClient, logger, mcache, nil),
// 		User:   userClient,
// 	}
// }
//
func StatsFrom(c *gin.Context) (s *Stats) {
	s, _ = c.Value(statsKey).(*Stats)
	return
}

func StatsWith(c *gin.Context, s *Stats) {
	c.Set(statsKey, s)
}

type Stats struct {
	Key *datastore.Key `datastore:"__key__"`
	// ID        string         `gae:"$id"`
	// Parent    *datastore.Key `gae:"$parent"`
	Turns     int
	Duration  time.Duration
	Longest   time.Duration
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (s *Stats) Load(ps []datastore.Property) error {
	return datastore.LoadStruct(s, ps)
}

func (s *Stats) Save() ([]datastore.Property, error) {
	t := time.Now()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = t
	}
	s.UpdatedAt = t
	return datastore.SaveStruct(s)
}

func (s *Stats) LoadKey(k *datastore.Key) error {
	s.Key = k
	return nil
}

type MultiStats []*Stats

func (s *Stats) Average() time.Duration {
	if s.Turns == 0 {
		return 0
	}
	return (s.Duration / time.Duration(s.Turns))
}

// last is time associated with last move in game.
func (s *Stats) Update(c *gin.Context, last time.Time) {
	StatsWith(c, s.update(last))
}

func (s *Stats) GetUpdate(c *gin.Context, last time.Time) *Stats {
	return s.update(last)
}

func (s *Stats) update(last time.Time) *Stats {
	since := time.Since(last)

	s.Turns += 1
	s.Duration += since
	if since > s.Longest {
		s.Longest = s.Duration
	}

	return s
}

func (s *Stats) AverageString() string {
	switch d := s.Average(); {
	case d.Minutes() < 60:
		return fmt.Sprintf("%.f minutes", d.Minutes())
	case d.Hours() < 48:
		return fmt.Sprintf("%.1f hours", d.Hours())
	default:
		return fmt.Sprintf("%.1f days", d.Hours()/24)
	}
}

func (s *Stats) LongestString() string {
	switch d := s.Longest; {
	case d.Minutes() < 60:
		return fmt.Sprintf("%.f minutes", d.Minutes())
	case d.Hours() < 48:
		return fmt.Sprintf("%.1f hours", d.Hours())
	default:
		return fmt.Sprintf("%.1f days", d.Hours()/24)
	}
}

func (s *Stats) SinceLastString() string {
	switch d := time.Since(time.Time(s.UpdatedAt)); {
	case d.Minutes() < 60:
		return fmt.Sprintf("%.f minutes", d.Minutes())
	case d.Hours() < 48:
		return fmt.Sprintf("%.1f hours", d.Hours())
	default:
		return fmt.Sprintf("%.1f days", d.Hours()/24)
	}
}

//func key(c *gin.Context, u *user.User) *datastore.Key {
//	return datastore.NewKey(ctx, kind, name, 0, u.Key)
//}

func NewStatsFor(u *User) *Stats {
	return &Stats{Key: statsKeyFor(u)}
}

func statsKeyFor(u *User) *datastore.Key {
	return datastore.NameKey(sKind, sName, u.Key)
}

func singleError(err error) error {
	if err == nil {
		return err
	}
	if me, ok := err.(datastore.MultiError); ok {
		return me[0]
	}
	return err
}

func (client *Client) StatsFor(c *gin.Context, u *User) (*Stats, error) {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgEnter)

	s, err := client.mcGetStatsFor(c, u)
	if err == nil {
		return s, nil
	}

	s, err = client.dsGetStatsFor(c, u)
	if err == datastore.ErrNoSuchEntity {
		return s, nil
	}
	return s, err
}

func (client *Client) StatsUpdate(c *gin.Context, s *Stats, last time.Time) (*Stats, error) {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgEnter)

	s.update(last)

	_, err := client.DS.Put(c, s.Key, s)
	if err != nil {
		return nil, err
	}

	client.Cache.SetDefault(s.Key.Encode(), s)
	return s, nil
}

func (client *Client) mcGetStatsFor(c *gin.Context, u *User) (*Stats, error) {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgEnter)

	if u == nil {
		return nil, ErrMissingUser
	}

	k := statsKeyFor(u)
	item, found := client.Cache.Get(k.Encode())
	if !found {
		return nil, ErrNotFound
	}

	s, ok := item.(*Stats)
	if !ok {
		return nil, ErrInvalidCache
	}

	return s, nil
}

func (client *Client) dsGetStatsFor(c *gin.Context, u *User) (*Stats, error) {
	client.Log.Debugf(msgEnter)
	defer client.Log.Debugf(msgEnter)

	if u == nil {
		return nil, ErrMissingUser
	}

	s := NewStatsFor(u)
	err := client.DS.Get(c, s.Key, s)
	if err != nil {
		return s, err
	}

	client.Cache.SetDefault(s.Key.Encode(), s)
	return s, nil
}

// func (client *Client) StatsForMulti(c *gin.Context, us []*User) ([]*Stats, error) {
// 	l := len(us)
// 	ss := make([]*Stats, l)
// 	ks := make([]*datastore.Key, l)
// 	for i := range ss {
// 		ss[i] = NewStats(c, us[i])
// 		ks[i] = ss[i].Key
// 	}
//
// 	err := client.DS.GetMulti(c, ks, ss)
// 	if err == nil {
// 		return ss, nil
// 	}
//
// 	me, ok := err.(datastore.MultiError)
// 	if !ok {
// 		return nil, err
// 	}
//
// 	// filter out ErrNoSuchEntity since the entity will not exist if the player has yet to take a turn.
// 	isNil := true
// 	for i, e := range me {
// 		if e != nil {
// 			if e == datastore.ErrNoSuchEntity {
// 				me[i] = nil
// 			} else {
// 				isNil = false
// 			}
// 		}
// 	}
//
// 	if isNil {
// 		return ss, nil
// 	}
// 	return nil, me
// }

func (client *Client) StatsFetch(c *gin.Context) {
	client.Log.Debugf("Entering")
	defer client.Log.Debugf("Exiting")

	if From(c) != nil {
		return
	}

	cu, err := client.Current(c)
	if err != nil {
		client.Log.Debugf(err.Error())
	}
	client.Log.Debugf("u: %#v", cu)
	if cu == nil {
		restful.AddErrorf(c, "missing user.")
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("missing user."))
		return
	}

	s, err := client.StatsFor(c, cu)
	if err != nil {
		restful.AddErrorf(c, err.Error())
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	StatsWith(c, s)
}

func StatsFetched(c *gin.Context) *Stats {
	return StatsFrom(c)
}
