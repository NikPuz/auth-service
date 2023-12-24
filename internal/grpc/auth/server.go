package auth

import (
	"context"
	authv1 "github.com/NikPuz/auth-service-proto/gen/go/authService"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type IAuthService interface {
	Login(ctx context.Context, email string, password string, appId int) (string, error)
	IsAdmin(ctx context.Context, userId int64) (bool, error)
	RegisterNewUser(ctx context.Context, email string, Password string) (int64, error)
}

type serverAPI struct {
	authv1.UnimplementedAuthServer
	auth IAuthService
}

func Register(gRPC *grpc.Server, authService IAuthService) {
	authv1.RegisterAuthServer(gRPC, &serverAPI{auth: authService})
}

func (s *serverAPI) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	if len(req.GetEmail()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if len(req.GetPassword()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	if req.GetAppId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "app_id is required")
	}

	token, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), int(req.GetAppId()))
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &authv1.LoginResponse{Token: token}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	if len(req.GetEmail()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if len(req.GetPassword()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	userId, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &authv1.RegisterResponse{UserId: userId}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *authv1.IsAdminRequest) (*authv1.IsAdminResponse, error) {
	if req.GetUserId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &authv1.IsAdminResponse{IsAdmin: isAdmin}, nil
}
