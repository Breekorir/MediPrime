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
