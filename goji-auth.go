package auth

import (
	"errors"
	"github.com/fluxxu/session"
	"github.com/jmoiron/sqlx"
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
	Dbx           *sqlx.DB
}

var opts *Opts
var sessionStore session.Store

func Configure(options *Opts) {
	opts = options

	sessionStore = session.NewMySQLStore(opts.Dbx.DB, 3600*24)

	mux := options.Mux
	mux.Use(sessionMiddleware)
	mux.Use(authMiddleware)

	mux.Get(opts.MuxBase+"/token", RouteGetUser)
	mux.Post(opts.MuxBase+"/token", RouteLogin)
	mux.Delete(opts.MuxBase+"/token", RouteLogout)
}
