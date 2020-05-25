package user

import (
	"errors"
	"fmt"

	"github.com/gofrs/uuid"
)

const (
	GAE_VERSION = "GAE_VERSION"

	kind              = "User"
	uidParam          = "uid"
	guserKey          = "guser"
	currentKey        = "current"
	userKey           = "User"
	countKey          = "count"
	homePath          = "/"
	salt              = "slothninja"
	usersKey          = "Users"
	HOST              = "HOST"
	authPath          = "/auth"
	sessionKey        = "session"
	userNewPath       = "/user/new"
	tokenLength       = 32
	uKind             = "User"
	oauthsKind        = "OAuths"
	oauthKind         = "OAuth"
	root              = "root"
	stateKey          = "state"
	NotFound    int64 = -1
	fqdn              = "www.slothninja.com"
	statsKind         = "Stats"
	statsName         = "root"
	statsKey          = "Stats"
	msgEnter          = "Entering"
	msgExit           = "Exiting"
)

var (
	namespaceUUID   = uuid.NewV5(uuid.NamespaceDNS, fqdn)
	ErrMissingToken = fmt.Errorf("missing token")
	ErrNotFound     = errors.New("User not found.")
	ErrTooManyFound = errors.New("Found too many users.")
)
