from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from datetime import timedelta
import os
from collections import defaultdict
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
from sqlalchemy import or_  # Required for filtering

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/sounds'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretgirlykey'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
ALLOWED_EXTENSIONS = {'mp3', 'wav'}

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False) 
    is_admin = db.Column(db.Boolean, default=False)
    favorites = db.relationship('Favorite', backref='user', lazy=True)

class Sound(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    category = db.Column(db.String(50))
    filename = db.Column(db.String(200)) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id')) 
    uploader = db.relationship('User', backref='sounds') 

class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sound_id = db.Column(db.Integer, db.ForeignKey('sound.id'), nullable=False)

# Helpers
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None
@app.template_filter('update_query_params')
def update_query_params(url, param, value):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = [str(value)]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))

@app.before_request
def make_session_permanent():
    session.permanent = True

# Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'user_id' not in session:
            flash("Please log in to upload sounds.", "warning")
            return redirect(url_for('login'))

        title = request.form.get('title')
        category = request.form.get('category')
        file = request.files.get('file')

        if not title or not category or not file:
            flash("Please fill in all fields and select a file.", "danger")
            return redirect(url_for('index'))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            counter = 1
            base, ext = os.path.splitext(filename)
            while os.path.exists(filepath):
                filename = f"{base}_{counter}{ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                counter += 1

            file.save(filepath)

            new_sound = Sound(
                title=title.strip(),
                category=category.strip(),
                filename=filename,
                user_id=session['user_id']
            )
            db.session.add(new_sound)
            db.session.commit()
            flash("Sound uploaded successfully!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid file type. Only MP3 and WAV allowed.", "danger")
            return redirect(url_for('index'))

    query = request.args.get('q', '').strip()
    if query:
        sounds = Sound.query.filter(
            or_(
                Sound.title.ilike(f'%{query}%'),
                Sound.category.ilike(f'%{query}%')
            )
        ).all()
    else:
        sounds = Sound.query.all()

    return render_template('index.html', sounds=sounds, user=current_user())

@app.route('/browse')
def browse():
    query = request.args.get('q', '').strip()
    selected_category = request.args.get('category', '').strip()
    per_page = 7  # ✅ Show 7 sounds per title

    # Base query
    sounds_query = Sound.query
    if query:
        sounds_query = sounds_query.filter(
            or_(
                Sound.title.ilike(f'%{query}%'),
                Sound.category.ilike(f'%{query}%')
            )
        )
    if selected_category:
        sounds_query = sounds_query.filter(Sound.category == selected_category)

    # Get all matching sounds and group by title
    all_sounds = sounds_query.order_by(Sound.title.asc()).all()
    grouped_sounds = defaultdict(list)
    for sound in all_sounds:
        grouped_sounds[sound.title].append(sound)

    # Apply pagination per title
    paginated_sounds = {}
    for title, sounds_list in grouped_sounds.items():
        page_param = f"{title}_page"
        page = request.args.get(page_param, 1, type=int)

        start = (page - 1) * per_page
        end = start + per_page
        paginated_items = sounds_list[start:end]
        has_next = end < len(sounds_list)

        paginated_sounds[title] = {
            'items': paginated_items,
            'current_page': page,
            'has_next': has_next,
            'page_param': page_param
        }

    categories = [c[0] for c in db.session.query(Sound.category).distinct().order_by(Sound.category).all()]
    user = current_user()
    user_favorite_ids = [fav.sound_id for fav in user.favorites] if user else []

    return render_template(
        'browse.html',
        paginated_sounds=paginated_sounds,
        categories=categories,
        selected_category=selected_category,
        user=user,
        user_favorite_ids=user_favorite_ids
    )
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        flash("Please log in to upload sounds.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title')
        category = request.form.get('category')
        file = request.files.get('file')

        if not title or not category or not file:
            flash("Please fill in all fields and select a file.", "danger")
            return redirect(url_for('upload'))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            counter = 1
            base, ext = os.path.splitext(filename)
            while os.path.exists(filepath):
                filename = f"{base}_{counter}{ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                counter += 1

            file.save(filepath)

            new_sound = Sound(title=title, category=category, filename=filename, user_id=session['user_id'])
            db.session.add(new_sound)
            db.session.commit()
            flash("Sound uploaded successfully!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid file type. Only MP3 and WAV allowed.", "danger")
            return redirect(url_for('upload'))

    return render_template('upload.html', user=current_user())

@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Email already registered. Please login.', 'warning')
            return redirect(url_for('login'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out.", "info")
    return redirect(url_for('index'))

@app.route('/favorites')
def favorites():
    user = current_user()
    if not user:
        flash("Please log in to view favorites.", "warning")
        return redirect(url_for('login'))

    favorite_sounds = [fav.sound_id for fav in user.favorites]
    sounds = Sound.query.filter(Sound.id.in_(favorite_sounds)).all()

    # Group by title just like in browse
    from collections import defaultdict
    paginated_sounds = defaultdict(lambda: {"items": [], "current_page": 1, "has_next": False})
    for sound in sounds:
        paginated_sounds[sound.title]["items"].append(sound)

    return render_template('favorites.html', paginated_sounds=paginated_sounds, user=user)

@app.route('/favorite/<int:sound_id>')
def favorite(sound_id):
    user = current_user()
    if not user:
        flash("Login required to save favorites.", "warning")
        return redirect(url_for('login'))

    if not Favorite.query.filter_by(user_id=user.id, sound_id=sound_id).first():
        fav = Favorite(user_id=user.id, sound_id=sound_id)
        db.session.add(fav)
        db.session.commit()
        flash("Added to favorites!", "success")

    return redirect(request.referrer or url_for('favorites'))
@app.route('/unfavorite/<int:sound_id>')
def unfavorite(sound_id):
    user = current_user()
    if not user:
        flash("Login required.", "warning")
        return redirect(url_for('login'))

    fav = Favorite.query.filter_by(user_id=user.id, sound_id=sound_id).first()
    if fav:
        db.session.delete(fav)
        db.session.commit()
        flash("Removed from favorites.", "info")

    return redirect(request.referrer or url_for('favorites'))
@app.route('/delete/<int:sound_id>', methods=['POST'])
def delete_sound(sound_id):
    sound = Sound.query.get_or_404(sound_id)
    user = current_user()

    if not user or (sound.user_id != user.id and not user.is_admin):
        flash("You can only delete your own uploaded sounds.", "danger")
        return redirect(url_for('index'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], sound.filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    db.session.delete(sound)
    db.session.commit()
    flash("Sound deleted successfully!", "success")
    return redirect(url_for('index'))

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    with app.app_context():
        db.create_all()
        if Sound.query.count() == 0:
            sample_sounds = [
                {"title": "Gentle Rain", "category": "Weather", "filename": "rain.mp3"},
                {"title": "Birds Chirping", "category": "Animals", "filename": "birds.wav"},
                {"title": "Laughing Crowd", "category": "Humans", "failename": "laugh.mp3"}
            ]
            for sound in sample_sounds:
                if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], sound['filename'])):
                    db.session.add(Sound(**sound))
            db.session.commit()

    app.run(debug=True)
