// main.go
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	http.HandleFunc("/user/", getUserHandler)
	log.Println("Starting server on :8085")
	http.ListenAndServe(":8084", nil)
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	fmt.Printf("Query params: %s\n", query)
	if query.Has("2"){
		println("yes 2")
	}
	
	user := getUserByID("Nikhil", "biggestString")
	fmt.Fprintf(w, "User: %d \n", user)
}

func getUserByID(name string, str string) int {
	println(str)
	db, err := sql.Open("sqlite3", "test.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var id int
	err = db.QueryRow("  SELECT id FROM users WHERE name = ?", name).Scan(&id)
	if err != nil {
		log.Fatal(err)
	}
	return id
}
