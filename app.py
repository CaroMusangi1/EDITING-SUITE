import subprocess
import wave
import numpy as np
import os
import tempfile
from io import BytesIO

from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename
from flask_cors import CORS
import cv2
from fpdf import FPDF

app = Flask(__name__)
CORS(app)

ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_audio(video_path, audio_path):
    command = [
        'ffmpeg', '-i', video_path,
        '-vn',  # no video
        '-acodec', 'pcm_s16le',  # 16-bit PCM wav
        '-ar', '44100',  # sample rate
        '-ac', '1',  # mono audio
        audio_path,
        '-y'  # overwrite output
    ]
    subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

def analyze_audio(audio_path, silence_threshold=500, clip_threshold=32000):
    with wave.open(audio_path, 'rb') as wav:
        n_frames = wav.getnframes()
        framerate = wav.getframerate()
        audio_data = wav.readframes(n_frames)
        audio_array = np.frombuffer(audio_data, dtype=np.int16)

    duration = n_frames / framerate
    rms = np.sqrt(np.mean(audio_array.astype(np.float64)**2))
    clipped_samples = np.sum(np.abs(audio_array) >= clip_threshold)
    clip_ratio = clipped_samples / n_frames
    silent_samples = np.sum(np.abs(audio_array) < silence_threshold)
    silent_ratio = silent_samples / n_frames

    issues = []
    if clip_ratio > 0.01:
        issues.append("Audio clipping detected")
    if silent_ratio > 0.5:
        issues.append("Long silence detected")
    if rms < 1000:
        issues.append("Audio volume is very low")

    return {
        'duration_seconds': round(duration, 2),
        'rms_volume': int(rms),
        'clipping_ratio': round(clip_ratio, 4),
        'silence_ratio': round(silent_ratio, 4),
        'issues': issues
    }

def is_blurry(frame, threshold=100):
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    variance = cv2.Laplacian(gray, cv2.CV_64F).var()
    return variance < threshold, variance

def analyze_video(video_path, threshold=100, sample_rate=5):
    cap = cv2.VideoCapture(video_path)
    blurry_frames = 0
    total_frames = 0
    variances = []
    frame_count = 0

    while True:
        ret, frame = cap.read()
        if not ret:
            break
        if frame_count % sample_rate == 0:
            total_frames += 1
            blurry, variance = is_blurry(frame, threshold)
            variances.append(variance)
            if blurry:
                blurry_frames += 1
        frame_count += 1

    cap.release()

    blurry_ratio = blurry_frames / total_frames if total_frames else 0
    average_variance = round(sum(variances) / len(variances), 2) if variances else 0
    clarity_score = (1 - blurry_ratio) * 100
    sharpness_score = min(average_variance / 1000 * 100, 100)
    quality_score = round((0.6 * clarity_score) + (0.4 * sharpness_score), 2)

    if quality_score >= 80:
        grade = "Excellent"
        issue = False
    elif quality_score > 50:
        grade = "Fair"
        issue = False
    else:
        grade = "Poor"
        issue = True

    return {
        'total_frames': total_frames,
        'blurry_frames': blurry_frames,
        'blurry_ratio': round(blurry_ratio, 3),
        'average_variance': average_variance,
        'quality_score_percent': quality_score,
        'quality_grade': grade,
        'issue_detected': issue
    }

def generate_pdf_report(results):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Video Quality Report", ln=True, align='C')

    pdf.cell(200, 10, txt="--- Video Analysis ---", ln=True)
    for key, value in results['video_analysis'].items():
        pdf.cell(200, 10, txt=f"{key.replace('_', ' ').title()}: {value}", ln=True)

    pdf.cell(200, 10, txt="--- Audio Analysis ---", ln=True)
    for key, value in results['audio_analysis'].items():
        if key == 'issues':
            issues_str = ", ".join(value) if value else "None"
            pdf.cell(200, 10, txt=f"Issues: {issues_str}", ln=True)
        else:
            pdf.cell(200, 10, txt=f"{key.replace('_', ' ').title()}: {value}", ln=True)

    buffer = BytesIO()
    pdf.output(buffer)
    buffer.seek(0)
    return buffer

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_video():
    try:
        if 'video' not in request.files:
            return jsonify({'error': 'No video uploaded'}), 400

        video_file = request.files['video']
        if video_file.filename == '' or not allowed_file(video_file.filename):
            return jsonify({'error': 'Unsupported file type'}), 400

        threshold = float(request.form.get('threshold', 100))
        sample_rate = int(request.form.get('sample_rate', 5))

        temp_dir = tempfile.mkdtemp()
        filename = secure_filename(video_file.filename)
        video_path = os.path.join(temp_dir, filename)
        video_file.save(video_path)

        # Analyze video
        video_results = analyze_video(video_path, threshold, sample_rate)

        # Extract audio and analyze
        audio_path = os.path.join(temp_dir, 'extracted_audio.wav')
        extract_audio(video_path, audio_path)
        audio_results = analyze_audio(audio_path)
        audio_results['quality_grade'] = calculate_audio_grade(audio_results)

        # Cleanup
        try:
            os.remove(video_path)
            os.remove(audio_path)
            os.rmdir(temp_dir)
        except Exception as cleanup_error:
            print(f"Cleanup failed: {cleanup_error}")

        combined_results = {
            'video_analysis': video_results,
            'audio_analysis': audio_results
        }
        return jsonify(combined_results)

    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/report', methods=['POST'])
def download_report():
    try:
        results = request.json
        pdf_file = generate_pdf_report(results)
        return send_file(pdf_file, as_attachment=True, download_name="video_audio_quality_report.pdf")
    except Exception as e:
        return jsonify({'error': str(e)}), 500
def calculate_audio_grade(audio):
    score = 0

    # RMS volume scoring
    if audio['rms_volume'] > 1000:
        score += 40
    elif audio['rms_volume'] >= 500:
        score += 20

    # Silence ratio scoring
    if audio['silence_ratio'] < 0.1:
        score += 40
    elif audio['silence_ratio'] <= 0.5:
        score += 20

    # Clipping ratio scoring
    if audio['clipping_ratio'] == 0:
        score += 20

    if score >= 80:
        grade = 'Excellent'
    elif score >= 50:
        grade = 'Fair'
    else:
        grade = 'Poor'
    return grade

if __name__ == '__main__':
    app.run(debug=True)
