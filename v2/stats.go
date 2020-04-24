package user

import (
	"fmt"
	"net/http"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/SlothNinja/log"
	"github.com/SlothNinja/restful"
	"github.com/gin-gonic/gin"
)

func StatsFrom(c *gin.Context) (s *Stats) {
	s, _ = c.Value(statsKey).(*Stats)
	return
}

func WithStats(c *gin.Context, s *Stats) {
	c.Set(statsKey, s)
}

type Stats struct {
	Key       *datastore.Key `datastore:"__key__"`
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
	WithStats(c, s.update(c, last))
}

func (s *Stats) GetUpdate(c *gin.Context, last time.Time) *Stats {
	return s.update(c, last)
}

func (s *Stats) update(c *gin.Context, last time.Time) *Stats {
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

func NewStats(c *gin.Context, u *User) *Stats {
	return &Stats{Key: datastore.NameKey(statsKind, statsName, u.Key)}
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

func (client Client) ByUser(c *gin.Context, u *User) (*Stats, error) {
	s := NewStats(c, u)
	err := client.DS.Get(c, s.Key, s)
	if err == datastore.ErrNoSuchEntity {
		return s, nil
	}
	return s, err
}

func (client Client) ByUsers(c *gin.Context, us []*User) ([]*Stats, error) {
	l := len(us)
	ss := make([]*Stats, l)
	ks := make([]*datastore.Key, l)
	for i := range ss {
		ss[i] = NewStats(c, us[i])
		ks[i] = ss[i].Key
	}

	err := client.DS.GetMulti(c, ks, ss)
	if err == nil {
		return ss, nil
	}

	me, ok := err.(datastore.MultiError)
	if !ok {
		return nil, err
	}

	// filter out ErrNoSuchEntity since the entity will not exist if the player has yet to take a turn.
	isNil := true
	for i, e := range me {
		if e != nil {
			if e == datastore.ErrNoSuchEntity {
				me[i] = nil
			} else {
				isNil = false
			}
		}
	}

	if isNil {
		return ss, nil
	}
	return nil, me
}

func (client Client) FetchStats(getUser func(*gin.Context) *User) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debugf("Entering")
		defer log.Debugf("Exiting")

		if From(c) != nil {
			return
		}

		u := getUser(c)
		log.Debugf("u: %#v", u)
		if u == nil {
			restful.AddErrorf(c, "missing user.")
			c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("missing user."))
			return
		}

		s, err := client.ByUser(c, u)
		if err != nil {
			restful.AddErrorf(c, err.Error())
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		WithStats(c, s)
	}
}

func FetchedStats(c *gin.Context) *Stats {
	return StatsFrom(c)
}
