package auth

import (
	"auth-service/internal/domain/models"
	"auth-service/internal/storage"
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type AuthService struct {
	log          *slog.Logger
	userSaver    IUserSaver
	userProvider IUserProvider
	appProvider  IAppProvider
	tokenTTL     time.Duration
}

type IUserSaver interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (uid int64, err error)
}

type IUserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userId int64) (bool, error)
}

type IAppProvider interface {
	App(ctx context.Context, appId int) (models.User, error)
}

func New(log *slog.Logger, userSaver IUserSaver, userProvider IUserProvider, appProvider IAppProvider, tokenTTL time.Duration) *AuthService {
	return &AuthService{
		log:          log,
		userSaver:    userSaver,
		userProvider: userProvider,
		appProvider:  appProvider,
		tokenTTL:     tokenTTL,
	}
}

func (a *AuthService) RegisterNewUser(ctx context.Context, email string, Password string) (int64, error) {
	const op = "authService.RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed generate password hash", err.Error())

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		log.Error("failed to save user", err.Error())

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (a *AuthService) Login(ctx context.Context, email string, password string, appId int) (string, error) {
	const op = "authService.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
		slog.String("password", password),
		slog.Int("appId", int(appId)),
	)

	log.Info("attempting to logging user")

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Error("user not found", err.Error())

			return "", fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		log.Error("failed get user", err.Error())

		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err = bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Error("invalid credentials", err.Error())

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appId)
	if err != nil {
		log.Error("failed to save user", err.Error())

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return app.Email, nil
}

func (a *AuthService) IsAdmin(ctx context.Context, userId int64) (bool, error) {
	panic("")
}
