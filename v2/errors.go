package user

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/SlothNinja/log"
	"github.com/gin-gonic/gin"
)

var (
	ErrValidation         = errors.New("validation error")
	ErrUnexpected         = errors.New("unexpected error")
	ErrUserNotFound       = fmt.Errorf("current user not found: %w", ErrValidation)
	ErrPlayerNotFound     = fmt.Errorf("player not found: %w", ErrValidation)
	ErrActionNotPerformed = fmt.Errorf("player has yet to perform an action: %w", ErrValidation)
	ErrNotAdmin           = fmt.Errorf("current user is not admin: %w", ErrValidation)
	ErrNotCurrentPlayer   = fmt.Errorf("current user is not current player: %w", ErrValidation)
)

func JErr(c *gin.Context, err error) {
	if errors.Is(err, ErrValidation) {
		c.JSON(http.StatusOK, gin.H{"message": err.Error()})
		return
	}
	log.Debugf(err.Error())
	c.JSON(http.StatusOK, gin.H{"message": ErrUnexpected.Error()})
}
