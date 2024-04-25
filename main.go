package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"

	pb "grpc/pb"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "" // provide your own username
	password = "" // provide your own password
	dbname   = "users"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

type server struct {
	pb.UnimplementedRegistrationServer
	db *sql.DB
}

func (s *server) SignUp(ctx context.Context, in *pb.SignUpRequest) (*pb.SignUpResponse, error) {
	hashedPassword, err := HashPassword(in.Password)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var exists bool
	err = s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 OR name = $2)", in.Email, in.Name).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, status.Error(codes.AlreadyExists, "user already exists")
	}

	if in.Password != in.ConfirmPassword {
		return nil, status.Error(codes.InvalidArgument, "passwords must match")

	}
	_, err = tx.ExecContext(ctx, "INSERT INTO users(email, name, password, timestamp) VALUES($1, $2, $3, NOW())",
		in.Email, in.Name, hashedPassword)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &pb.SignUpResponse{
		Response: "signup successful",
	}, nil
}

func (s *server) Login(ctx context.Context, in *pb.LoginRequest) (*pb.LoginResponse, error) {
	statement, err := s.db.Prepare("SELECT password FROM users WHERE name = $1 OR email = $1")
	if err != nil {
		log.Fatalf("failed to prepare statement: %v", err)
	}
	defer statement.Close()

	row := statement.QueryRowContext(ctx, in.NameOrEmail)

	var hashedPassword string
	if err := row.Scan(&hashedPassword); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "user doesn't exist")
		}
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(in.Password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return nil, status.Error(codes.InvalidArgument, "incorrect password")
		}
		return nil, err
	}

	return &pb.LoginResponse{
		Response: "login successful",
	}, nil
}

func main() {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	reflection.Register(s)
	pb.RegisterRegistrationServer(s, &server{db: db})
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
