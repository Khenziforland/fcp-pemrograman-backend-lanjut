package handler

import (
	"a21hc3NpZ25tZW50/client"
	"a21hc3NpZ25tZW50/model"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

var UserLogin = make(map[string]model.User)

// DESC: func Auth is a middleware to check user login id, only user that already login can pass this middleware
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("user_login_id")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
			return
		}

		if _, ok := UserLogin[c.Value]; !ok || c.Value == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "userID", c.Value)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// DESC: func AuthAdmin is a middleware to check user login role, only admin can pass this middleware
func AuthAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("user_login_role")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
			return
		}

		if c.Value != "admin" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login role not Admin"})
			return
		}

		userLoginId, err := r.Cookie("user_login_id")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "userRole", c.Value)
		ctx = context.WithValue(ctx, "userLoginId", userLoginId.Value)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}


func Login(w http.ResponseWriter, r *http.Request) {
	// Check if Method == Post
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(`{"error":"Method is not allowed!"}`))
		return
	}

	// Read request body
	body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"Bad request body"}`))
			return
		}

	var loginUser model.UserLogin
	err = json.Unmarshal(body, &loginUser)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"Failed to unmarshal request body"}`))
		return
	}

	// Check if Input Empty
	if loginUser.ID == "" || loginUser.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"ID or name is empty"}`))
		return
	}

	// Baca file users.txt
	users, err := ioutil.ReadFile("data/users.txt")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// cek apabila sudah ada di map login
	fmt.Println(loginUser, UserLogin, string(users))
	if data, exist := UserLogin[loginUser.ID]; exist {
		http.SetCookie(w, &http.Cookie{Name: "user_login_id", Value: data.ID})
		http.SetCookie(w, &http.Cookie{Name: "user_login_role", Value: data.Role})

		response := fmt.Sprintf(`{"username":"%s","message":"login success"}`, loginUser.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
		return
	}

	// Cari user berdasarkan ID & Name
	userFound := false
	var foundUser model.User
	for _, user := range strings.Split(string(users), "\n") {
		if user == "" {
			continue
		}
		parts := strings.Split(user, "_")
		if len(parts) < 4 {
			continue
		}
		if parts[0] == loginUser.ID {
			userFound = true
			foundUser.ID = parts[0]
			foundUser.Name = parts[1]
			foundUser.StudyCode = parts[2]
			foundUser.Role = parts[3]
			break
		}
	}

	// Jika user tidak ditemukan
	if !userFound {
		http.Error(w, `{"error":"user not found"}`, http.StatusBadRequest)
		return
	}

	// Berikan response success
	http.SetCookie(w, &http.Cookie{Name: "user_login_id", Value: foundUser.ID})
	http.SetCookie(w, &http.Cookie{Name: "user_login_role", Value: foundUser.Role})
	response := fmt.Sprintf(`{"username":"%s","message":"login success"}`, loginUser.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))

	// Tambahkan user login ke dalam Map
	UserLogin[foundUser.ID] = foundUser
}

func Register(w http.ResponseWriter, r *http.Request) {
	// Check if Method == Post
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(`{"error":"Method is not allowed!"}`))
		return
	}

	// Read request body
	body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"Bad request body"}`))
			return
		}

	var newUser model.User
	err = json.Unmarshal(body, &newUser)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"Failed to unmarshal request body"}`))
		return
	}

	// Check if Input Empty
	if newUser.ID == "" || newUser.Name == "" || newUser.Role == ""|| newUser.StudyCode == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"ID, name, study code or role is empty"}`))
		return
	}

	// Check Role
	if newUser.Role != "admin" && newUser.Role != "user" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"role must be admin or user"}`))
		return
	}

	// Check if study code exists
		studies, err := ioutil.ReadFile("data/list-study.txt")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"Failed to read studies data"}`))
			return
		}

		if !strings.Contains(string(studies), newUser.StudyCode) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"study code not found"}`))
			return
		}

	// Check if user ID already exists
		users, err := ioutil.ReadFile("data/users.txt")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"Failed to read users data"}`))
			return
		}

		if strings.Contains(string(users), newUser.ID) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"user id already exist"}`))
			return
		}

		// Append new user to users file
		err = ioutil.WriteFile("data/users.txt", []byte(fmt.Sprintf("%s_%s_%s_%s\n", newUser.ID, newUser.Name, newUser.StudyCode, newUser.Role)), 0644)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"Failed to write user data"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`{"username":"%s","message":"register success"}`, newUser.ID)))
}

func Logout(w http.ResponseWriter, r *http.Request) {
	// Check if Method == Post
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(`{"error":"Method is not allowed!"}`))
		return
	}

	// Check if user already login
	userID := r.Context().Value("userID").(string)
	user, exist := UserLogin[userID]
	if !exist {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
		return
	}

	// Hapus cookie dan data user yang login
	delete(UserLogin, userID)
	http.SetCookie(w, &http.Cookie{Name: "user_login_id", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "user_login_role", MaxAge: -1})

	// Berikan response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"username":"%s","message":"logout success"}`, user.ID)))
}

func GetStudyProgram(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error":"Method is not allowed!"}`)
		return
	}

	// Check if user already login
	userID := r.Context().Value("userID").(string)
	_, exist := UserLogin[userID]
	if !exist {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
		return
	}

	data, err := ioutil.ReadFile("data/list-study.txt")
	if err != nil {
		log.Fatal(err)
	}

	lines := strings.Split(string(data), "\n")
	var studyData []model.StudyData
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "_")
		if len(fields) != 2 {
			log.Fatalf("Invalid data format: %s", line)
		}
		studyData = append(studyData, model.StudyData{
			Code: fields[0],
			Name: fields[1],
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(studyData)
}

func AddUser(w http.ResponseWriter, r *http.Request) {
	// Check if Method == Post
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(`{"error":"Method is not allowed!"}`))
		return
	}

	// Check user login
	userID, ok := r.Context().Value("userID").(string)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
		return
	}

	// Check admin role
	userRole := r.Context().Value("userRole").(string)
	if userRole != UserLogin[userID].Role {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login role not Admin"})
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"Bad request body"}`))
		return
	}

	var newUser model.User
	err = json.Unmarshal(body, &newUser)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"Failed to unmarshal request body"}`))
		return
	}

	if newUser.ID == "" || newUser.Name == "" || newUser.StudyCode == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"ID, name, or study code is empty"}`))
		return
	}

	// check if user ID already exists
	users, err := ioutil.ReadFile("data/users.txt")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Failed to read users data"}`))
		return
	}

	if strings.Contains(string(users), newUser.ID) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"user id already exist"}`))
		return
	}

	// check if study code exists
	studies, err := ioutil.ReadFile("data/list-study.txt")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Failed to read studies data"}`))
		return
	}

	if !strings.Contains(string(studies), newUser.StudyCode) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"study code not found"}`))
		return
	}

	// append new user to users file
	err = ioutil.WriteFile("data/users.txt", []byte(fmt.Sprintf("%s_%s_%s\n", newUser.ID, newUser.Name, newUser.StudyCode)), 0644)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Failed to write user data"}`))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"username":"%s","message":"add user success"}`, newUser.ID)))
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
	w.WriteHeader(http.StatusMethodNotAllowed)
	w.Write([]byte(`{"error":"Method is not allowed!"}`))
	return
	}

	// Check user login
	userID, ok := r.Context().Value("userID").(string)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
		return
	}

	// Check admin role
	userRole := r.Context().Value("userRole").(string)
	if userRole != UserLogin[userID].Role {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login role not Admin"})
		return
	}

	// Cek query parameter
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"user id is empty"}`, http.StatusBadRequest)
		return
	}

	// Baca file users.txt
	users, err := ioutil.ReadFile("data/users.txt")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Cari user berdasarkan ID
	userFound := false
	var newUsers []string
	for _, user := range strings.Split(string(users), "\n") {
		if user == "" {
			continue
		}
		parts := strings.Split(user, "_")
		if parts[0] == id {
			userFound = true
			continue
		}
		newUsers = append(newUsers, user)
	}

	// Jika user tidak ditemukan
	if !userFound {
		http.Error(w, `{"error":"user id not found"}`, http.StatusBadRequest)
		return
	}

	// Simpan kembali data user yang masih ada
	newContent := strings.Join(newUsers, "\n")
	if err := ioutil.WriteFile("data/users.txt", []byte(newContent), 0644); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Berikan response success
	response := fmt.Sprintf(`{"username":"%s","message":"delete success"}`, id)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
}

// DESC: Gunakan variable ini sebagai goroutine di handler GetWeather
var GetWetherByRegionAPI = client.GetWeatherByRegion

func GetWeather(w http.ResponseWriter, r *http.Request) {
// 	var listRegion = []string{"jakarta", "bandung", "surabaya", "yogyakarta", "medan", "makassar", "manado", "palembang", "semarang", "bali"}

// 	weatherCh := make(chan model.Weather, len(listRegion))
// 	errCh := make(chan error)
// 	output := make([]model.MainWeather, 0)

// 	// DESC: dapatkan data weather dari 10 data di atas menggunakan goroutine
// 	for _, val := range listRegion {
// 		go wrappingWeather(val, weatherCh, errCh)
// 	}

// 	for i := 0; i < len(listRegion); i++ {
// 		err := <- errCh
// 		data := <- weatherCh
// 		if err != nil {
// 			w.WriteHeader(http.StatusInternalServerError)
// 			w.Write([]byte("Failed at Get Weather"))
// 			return
// 		}

// 		output = append(output,data)
// 	}
// 	w.WriteHeader(http.StatusOK)
// 	w.Write([]byte(output))
	
// }

// func wrappingWeather(daerah string, weatherCh chan model.MainWeather, errCh chan error) {
// 	respW, err := client.GetWeatherByRegion(daerah)
// 	if err != nil {
// 		errCh <- err
// 		return
// 	}
// 	weatherCh <- respW
// 	errCh <- nil
}




