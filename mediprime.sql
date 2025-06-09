CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL,
  email VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role ENUM('admin', 'user') DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE medicines (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  location VARCHAR(255) NOT NULL,
  availability BOOLEAN DEFAULT TRUE,
  added_by INT,
  FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE issues (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  title VARCHAR(255),
  description TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
INSERT INTO users (username, email, password, role) VALUES
('Admin User', 'admin@mediprime.com', '$2b$10$wJ2xw/KXhK0mX5vXfPOM1gFXYoBGGJeDqkU.tJ6VsIUl9h1rdsOWi', 'admin'),
('User One', 'user1@mediprime.com', '$2b$10$k3KHhWiFgVdJgd2xl8vMreB3c9ltVx3Gl9XXLzjDdERpmWo3ts1b.', 'user');
INSERT INTO medicines (name, location, availability, added_by) VALUES
('Paracetamol', 'Nairobi Hospital Pharmacy', TRUE, 1),
('Ibuprofen', 'Aga Khan Pharmacy - Nairobi', TRUE, 1),
('Amoxicillin', 'Karen Hospital', FALSE, 1),
('Vitamin C', 'City Chemist, Nairobi CBD', TRUE, 2),
('Cetirizine', 'Kenyatta Hospital Pharmacy', TRUE, 2);
-- Create the database if it doesn't exist
CREATE DATABASE IF NOT EXISTS mediprime_db;

-- Use the database
USE mediprime_db;

-- Table for Users (including admin and regular users)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') DEFAULT 'user', -- 'user' or 'admin'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for Pharmacies
CREATE TABLE IF NOT EXISTS pharmacies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    address VARCHAR(255),
    phone VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for Medicines
CREATE TABLE IF NOT EXISTS medicines (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    location VARCHAR(255) NOT NULL,
    availability INT NOT NULL DEFAULT 0,
    category VARCHAR(255),
    pharmacy_id INT,
    pharmacy_name VARCHAR(255), -- Denormalized for easier display
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pharmacy_id) REFERENCES pharmacies(id) ON DELETE CASCADE
);

-- Table for Orders
CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    medicine_id INT NOT NULL,
    quantity INT NOT NULL,
    status ENUM('pending', 'completed', 'cancelled') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (medicine_id) REFERENCES medicines(id) ON DELETE CASCADE
);

-- Seed Data

-- Clear existing data (optional, for fresh start)
-- TRUNCATE TABLE orders;
-- TRUNCATE TABLE medicines;
-- TRUNCATE TABLE pharmacies;
-- TRUNCATE TABLE users;

-- Seed Users
INSERT IGNORE INTO users (username, email, password, role) VALUES
('Admin User', 'admin@example.com', '$2b$10$wT5Hqj2kLp.s.X.1.X.9.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.', 'admin'), -- Password: adminpassword
('John Doe', 'john@example.com', '$2b$10$wT5Hqj2kLp.s.X.1.X.9.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.', 'user'),   -- Password: userpassword
('Jane Smith', 'jane@example.com', '$2b$10$wT5Hqj2kLp.s.X.1.X.9.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.', 'user');   -- Password: userpassword

-- Seed Pharmacies
INSERT IGNORE INTO pharmacies (name, email, password, address, phone) VALUES
('City Pharmacy', 'citypharmacy@example.com', '$2b$10$wT5Hqj2kLp.s.X.1.X.9.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.', '123 Main St, Anytown', '555-1234'), -- Password: pharmacypassword
('Health Hub', 'healthhub@example.com', '$2b$10$wT5Hqj2kLp.s.X.1.X.9.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.X.', '456 Oak Ave, Anytown', '555-5678');  -- Password: pharmacypassword

-- Seed Medicines (assuming pharmacy_id 1 is City Pharmacy and 2 is Health Hub)
INSERT IGNORE INTO medicines (name, location, availability, category, pharmacy_id, pharmacy_name) VALUES
('Paracetamol', 'Shelf A1', 100, 'Pain Relief', 1, 'City Pharmacy'),
('Amoxicillin', 'Fridge B2', 50, 'Antibiotics', 1, 'City Pharmacy'),
('Ibuprofen', 'Shelf A2', 75, 'Pain Relief', 2, 'Health Hub'),
('Lisinopril', 'Shelf C3', 30, 'Blood Pressure', 2, 'Health Hub'),
('Cetirizine', 'Shelf A3', 120, 'Allergy', 1, 'City Pharmacy'),
('Metformin', 'Shelf B1', 60, 'Diabetes', 2, 'Health Hub');

-- Seed Orders (assuming user_id 2 is John Doe, 3 is Jane Smith)
-- And medicine_id 1 is Paracetamol (from City Pharmacy), 3 is Ibuprofen (from Health Hub)
INSERT IGNORE INTO orders (user_id, medicine_id, quantity, status) VALUES
(2, 1, 2, 'pending'),
(3, 3, 1, 'completed'),
(2, 5, 3, 'pending');