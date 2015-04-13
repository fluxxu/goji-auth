package auth

import (
	"errors"
	"github.com/fluxxu/session"
	"github.com/zenazn/goji/web"
	"net/http"
)

var ErrUserNotFound = errors.New("user not found")

// abstract user
type UserInterface interface {
	GetEmail() string
	GetDisplayName() string
}

type UserFinderInterface interface {
	FindUserByEmailAndPassword(email, password string) (UserInterface, error)
}

type AccessCheckerInterface interface {
	Check(r *http.Request, user UserInterface) (bool, error)
}

type Opts struct {
	UserFinder    UserFinderInterface
	AccessChecker AccessCheckerInterface
	Mux           *web.Mux
	MuxBase       string
	SessionStore  session.Store
}

var opts *Opts
var sessionStore session.Store
var userFinder UserFinderInterface
var muxBase string

var routeConfigured bool

func Configure(options *Opts) {
	opts = options

	if opts.SessionStore != nil {
		sessionStore = opts.SessionStore
	}

	if opts.UserFinder != nil {
		userFinder = opts.UserFinder
	}

	if !routeConfigured {
		routeConfigured = true
		mux := options.Mux
		mux.Use(sessionMiddleware)
		mux.Use(authMiddleware)

		muxBase = opts.MuxBase

		mux.Get(muxBase+"/token", RouteGetUser)
		mux.Post(muxBase+"/token", RouteLogin)
		mux.Delete(muxBase+"/token", RouteLogout)
	}
}
