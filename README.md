# MediPrime 🏥💊

MediPrime is a full-stack web application for tracking and finding medicine availability across various pharmacies. The platform allows both individuals and pharmacies to register, login, and interact with the system based on their roles.It also allows users to search for medicines, view their availability, and get notified when a medicine is available.It allows users to order the available medicines.

---

## 🌐 Features

* 🧑‍⚕️ Individual and Pharmacy registration
* 🔐 Role-based login and dashboards
* 🔍 Search medicines by name, location, or availability
* 🏥 Pharmacies can manage their own medicine listings
* �� Admin dashboard with medicine stats
* ✉️ Session-based authentication using `express-session`

---

## 📦 Tech Stack

* **Backend:** Node.js, Express
* **Frontend:** EJS (Embedded JavaScript Templates)
* **Database:** MySQL
* **Authentication:** bcrypt, express-session

---

## 🚀 Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/your-username/mediprime.git
cd mediprime
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure your MySQL database

Create a database called `mediprime_db` and run the following SQL:

```sql
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100),
  email VARCHAR(100) UNIQUE,
  password VARCHAR(255),
  role ENUM('user', 'pharmacy', 'admin') DEFAULT 'user'
);

CREATE TABLE medicines (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100),
  location VARCHAR(100),
  availability ENUM('available', 'unavailable') DEFAULT 'available',
  pharmacy_id INT,
  FOREIGN KEY (pharmacy_id) REFERENCES users(id)
);
```

Update the MySQL connection in `server.js`:

```js
const db = mysql.createConnection({
  host: "localhost",
  user: "your_mysql_user",
  password: "your_mysql_password",
  database: "mediprime_db"
});
```

### 4. Run the app

```bash
node server.js
```

Visit: [http://localhost:3000](http://localhost:3000)

---

## 🔪 Sample Credentials

You can register as:

* **Individual** – Can search for medicines
* **Pharmacy** – Can add/edit their own medicine listings

---

## 📁 Folder Structure

```
mediprime/
│
├── views/               # EJS templates
├── public/              # CSS and static files
├── server.js            # Main Express server
├── package.json
└── README.md
```

---

## 🙌 Contributions

Feel free to fork the project and submit pull requests for new features or improvements!

---

## 📃 License

This project is open-source and free to use.
