package mongo

import (
	"context"
	"os"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func InitMongoClient() (*mongo.Client, error) {
	mongoClient, err := mongo.Connect(context.Background(), options.Client().ApplyURI(os.Getenv("MONGO_URL")))
	if err != nil {
		return nil, err
	}

	return mongoClient, nil

}
