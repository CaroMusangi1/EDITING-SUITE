# 🎧 Sound Studio Resources

**Sound Studio Resources** is a Flask-based web app that helps media and film students explore, preview, and download categorized sound effects for creative projects. It features secure user login, grouped pagination by sound title, favorites, and admin moderation for inappropriate uploads.

---

## **🚀 Features**

- **🔐 User Authentication**
  - Register/Login/Logout functionality
  - Passwords securely hashed with Bcrypt
  - Admins can delete any uploaded sound

- **📤 Sound Uploads**
  - Accepts `.mp3` and `.wav` formats
  - Auto-renames files to avoid name collisions

- **📁 Browse Sounds**
  - Groups sounds by title (e.g., Rain, Applause)
  - Paginated: 9 sounds per title, with “More from [Title]” buttons

- **🔍 Search & Filter**
  - Search by title or category
  - Dropdown filter by category

- **🎧 Sound Previews & Downloads**
  - Built-in audio player for quick listening
  - One-click download buttons

- **⭐ Favorite Sounds**
  - Logged-in users can favorite/unfavorite sounds
  - “My Favorites” page to view personalized list

- **📧 Email Notification**
  - Sends welcome email on registration using Gmail SMTP

- **📱 Mobile-Friendly Design**
  - Bootstrap-based UI for responsive layout

---

## **🛠 Tech Stack**

- **Backend**: Python, Flask, Flask-Bcrypt, SQLAlchemy, Flask-Migrate
- **Frontend**: Jinja2, HTML, Bootstrap
- **Database**: SQLite
- **Email**: SMTP via Gmail (`smtplib`)

---

## **📁 Project Structure**
project/
├── static/
│ └── sounds/
├── templates/
│ ├── base.html
│ ├── browse.html
│ ├── login.html
│ ├── upload.html
│ ├── register.html
│ └── partials/
│ └── sound_cards.html
├── app.py
├── database.db
├── requirements.txt
└── .env

---

## **⚙️ Installation & Setup**

### 1. Clone the Repository

```bash
git clone https://github.com/CaroMusangi1/EDITING-SUITE.git
cd sound_bank
---
```
### 2. Create and Activate Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate 
```
### 3. Install Dependencies
```bash
pip install -r requirements.txt
```
### 4.Run App
```bash
python app.py
```
### 🛠 Future Improvements
Add waveform preview using wavesurfer.js
Cloud sound storage (e.g., AWS S3)
Sound tagging and comments
Admin dashboard

### 📧 Contact
Have questions or suggestions?
📩 Email: kitongacarol8@gnmail.com

### 📄 License
This project is open-sourced under the MIT License.


