
from fastapi import FastAPI, UploadFile, File, Form

from fastapi.middleware.cors import CORSMiddleware

import pdfplumber

import fitz  # PyMuPDF

from pypdf import PdfReader

from PIL import Image

import os

import shutil

try:

    import pytesseract

    OCR_AVAILABLE = True

    _tesseract_cmd = shutil.which("tesseract")

    if not _tesseract_cmd:

        _windows_tesseract = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

        if os.path.exists(_windows_tesseract):

            _tesseract_cmd = _windows_tesseract

    if _tesseract_cmd:

        pytesseract.pytesseract.tesseract_cmd = _tesseract_cmd

except ImportError:

    pytesseract = None

    OCR_AVAILABLE = False

import io

import re

import hashlib

import secrets

from datetime import datetime, timedelta, timezone

import smtplib
from email.message import EmailMessage

from pymongo import MongoClient

from bson import ObjectId

# =========================================================

# APP CONFIGURATION

# =========================================================

app = FastAPI(

    title="CareerAI Resume Analyzer",

    description="Backend API for analyzing resumes",

    version="1.0.0"

)

# =========================================================

# MONGODB DATABASE

# =========================================================

MONGO_URL = "mongodb://localhost:27017"

client = MongoClient(MONGO_URL)

db = client["careerai"]

users_collection = db["users"]

resume_analyses_collection = db["resume_analyses"]

# ATS Checker collection

ats_analyses_collection = db["ats_analyses"]

# JD Matcher collection

jd_matches_collection = db["jd_matches"]

try:

    client.admin.command("ping")

    print("MongoDB connected successfully!")

except Exception as e:

    print(f"MongoDB connection failed: {e}")

# =========================================================

# CORS

# =========================================================

app.add_middleware(

    CORSMiddleware,

    allow_origins=[

        "http://localhost:5173",

        "http://127.0.0.1:5173"

    ],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],

)

# =========================================================

# HOME

# =========================================================

@app.get("/")

def home():

    return {

        "message": "CareerAI Backend is running"

    }

# =========================================================

# DATABASE TEST

# =========================================================

@app.get("/api/db-test")

def database_test():

    try:

        client.admin.command("ping")

        return {

            "success": True,

            "message": "MongoDB connection is working",

            "database": "careerai"

        }

    except Exception as e:

        return {

            "success": False,

            "message": f"MongoDB connection failed: {str(e)}"

        }

# =========================================================

# AUTHENTICATION HELPERS

# =========================================================

def hash_password(password):

    """Create a salted password hash for MongoDB storage."""

    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(

        "sha256",

        password.encode("utf-8"),

        salt,

        100_000

    )

    return (salt + password_hash).hex()

def verify_password(password, stored_hash):

    """Verify a plain password against its stored salted hash."""

    try:

        stored_bytes = bytes.fromhex(stored_hash)

        salt = stored_bytes[:16]

        original_hash = stored_bytes[16:]

        password_hash = hashlib.pbkdf2_hmac(

            "sha256",

            password.encode("utf-8"),

            salt,

            100_000

        )

        return secrets.compare_digest(

            password_hash,

            original_hash

        )

    except (ValueError, TypeError):

        return False

def public_user(user):

    """Return user data that is safe to send to frontend."""

    return {

        "id": str(user["_id"]),

        "name": user["name"],

        "email": user["email"]

    }

# =========================================================

# AUTHENTICATION

# =========================================================

@app.post("/api/auth/register")

def register_user(data: dict):

    name = data.get("name", "").strip()

    email = data.get("email", "").strip().lower()

    password = data.get("password", "")

    if not name:

        return {

            "success": False,

            "message": "Name is required."

        }

    if not email:

        return {

            "success": False,

            "message": "Email is required."

        }

    if not re.match(

        r"^[^\s@]+@[^\s@]+\.[^\s@]+$",

        email

    ):

        return {

            "success": False,

            "message": "Please enter a valid email address."

        }

    if len(password) < 6:

        return {

            "success": False,

            "message": "Password must be at least 6 characters long."

        }

    existing_user = users_collection.find_one(

        {"email": email}

    )

    if existing_user:

        return {

            "success": False,

            "message": "An account with this email already exists."

        }

    user = {

        "name": name,

        "email": email,

        "password_hash": hash_password(password)

    }

    result = users_collection.insert_one(user)

    user["_id"] = result.inserted_id

    return {

        "success": True,

        "message": "Account created successfully.",

        "user": public_user(user)

    }

@app.post("/api/auth/login")

def login_user(data: dict):

    email = data.get("email", "").strip().lower()

    password = data.get("password", "")

    if not email or not password:

        return {

            "success": False,

            "message": "Email and password are required."

        }

    user = users_collection.find_one(

        {"email": email}

    )

    if not user or not verify_password(

        password,

        user.get("password_hash", "")

    ):

        return {

            "success": False,

            "message": "Invalid email or password."

        }

    return {

        "success": True,

        "message": "Login successful.",

        "user": public_user(user)

    }


# =========================================================
# PASSWORD RESET - EMAIL OTP
# =========================================================

# Configure these environment variables in backend/.env:
# SMTP_HOST, SMTP_PORT, SMTP_EMAIL, SMTP_PASSWORD, EMAIL_FROM
# For Gmail, use an App Password (not your normal Gmail password).

def send_otp_email(recipient_email, otp):
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_email = os.getenv("SMTP_EMAIL", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    sender_email = os.getenv("EMAIL_FROM", smtp_email)

    if not smtp_email or not smtp_password or not sender_email:
        raise RuntimeError("Email service is not configured. Set SMTP_EMAIL, SMTP_PASSWORD and EMAIL_FROM in backend/.env.")

    message = EmailMessage()
    message["Subject"] = "Your CareerAI password reset OTP"
    message["From"] = sender_email
    message["To"] = recipient_email
    message.set_content(
        f"""Hello,

Your CareerAI password reset OTP is: {otp}

This OTP expires in 10 minutes. Do not share it with anyone.
If you did not request a password reset, you can ignore this email.

CareerAI Team"""
    )

    with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
        server.starttls()
        server.login(smtp_email, smtp_password)
        server.send_message(message)


def hash_otp(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@app.post("/api/auth/forgot-password")
def forgot_password(data: dict):
    email = data.get("email", "").strip().lower()
    if not email or not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        return {"success": False, "message": "Please enter a valid email address."}

    user = users_collection.find_one({"email": email})
    # Generic response avoids revealing whether an account exists.
    if not user:
        return {
            "success": True,
            "message": "If an account exists for this email, a password reset OTP will be sent."
        }

    now = datetime.now(timezone.utc)
    last_sent = user.get("otp_sent_at")
    if last_sent:
        if last_sent.tzinfo is None:
            last_sent = last_sent.replace(tzinfo=timezone.utc)
        if now - last_sent < timedelta(seconds=60):
            return {
                "success": False,
                "message": "Please wait 60 seconds before requesting another OTP."
            }

    otp = f"{secrets.randbelow(1_000_000):06d}"
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "reset_otp_hash": hash_otp(otp),
            "reset_otp_expires_at": now + timedelta(minutes=10),
            "reset_otp_attempts": 0,
            "reset_otp_sent_at": now,
            "reset_otp_verified": False,
            "reset_token_hash": None,
            "reset_token_expires_at": None
        }}
    )

    try:
        send_otp_email(email, otp)
    except Exception as e:
        print(f"Password reset email error: {e}")
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$unset": {
                "reset_otp_hash": "",
                "reset_otp_expires_at": "",
                "reset_otp_attempts": "",
                "reset_otp_sent_at": ""
            }}
        )
        return {
            "success": False,
            "message": "Unable to send OTP email. Please check the email configuration and try again."
        }

    return {
        "success": True,
        "message": "If an account exists for this email, a password reset OTP will be sent."
    }


@app.post("/api/auth/verify-otp")
def verify_reset_otp(data: dict):
    email = data.get("email", "").strip().lower()
    otp = str(data.get("otp", "")).strip()

    if not email or not re.fullmatch(r"\d{6}", otp):
        return {"success": False, "message": "Enter your email and valid 6-digit OTP."}

    user = users_collection.find_one({"email": email})
    if not user or not user.get("reset_otp_hash"):
        return {"success": False, "message": "Invalid or expired OTP. Please request a new one."}

    now = datetime.now(timezone.utc)
    expires_at = user.get("reset_otp_expires_at")
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if not expires_at or now > expires_at:
        return {"success": False, "message": "OTP has expired. Please request a new one."}

    attempts = int(user.get("reset_otp_attempts", 0))
    if attempts >= 5:
        return {"success": False, "message": "Too many incorrect attempts. Please request a new OTP."}

    if not secrets.compare_digest(hash_otp(otp), user["reset_otp_hash"]):
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$inc": {"reset_otp_attempts": 1}}
        )
        return {"success": False, "message": "Incorrect OTP. Please try again."}

    reset_token = secrets.token_urlsafe(32)
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "reset_otp_verified": True,
            "reset_token_hash": hash_otp(reset_token),
            "reset_token_expires_at": now + timedelta(minutes=10)
        }}
    )

    return {
        "success": True,
        "message": "OTP verified successfully.",
        "reset_token": reset_token
    }


@app.post("/api/auth/reset-password")
def reset_password(data: dict):
    email = data.get("email", "").strip().lower()
    reset_token = data.get("reset_token", "")
    new_password = data.get("new_password", "")

    if not email or not reset_token or not new_password:
        return {"success": False, "message": "Email, reset token and new password are required."}

    if len(new_password) < 6:
        return {"success": False, "message": "Password must be at least 6 characters long."}

    user = users_collection.find_one({"email": email})
    if not user or not user.get("reset_otp_verified") or not user.get("reset_token_hash"):
        return {"success": False, "message": "Password reset session is invalid. Verify OTP again."}

    now = datetime.now(timezone.utc)
    token_expires_at = user.get("reset_token_expires_at")
    if token_expires_at and token_expires_at.tzinfo is None:
        token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)

    if not token_expires_at or now > token_expires_at:
        return {"success": False, "message": "Password reset session expired. Request a new OTP."}

    if not secrets.compare_digest(hash_otp(reset_token), user["reset_token_hash"]):
        return {"success": False, "message": "Invalid password reset session."}

    users_collection.update_one(
        {"_id": user["_id"]},
        {
            "$set": {"password_hash": hash_password(new_password)},
            "$unset": {
                "reset_otp_hash": "",
                "reset_otp_expires_at": "",
                "reset_otp_attempts": "",
                "reset_otp_sent_at": "",
                "reset_otp_verified": "",
                "reset_token_hash": "",
                "reset_token_expires_at": ""
            }
        }
    )

    return {"success": True, "message": "Password reset successfully. Please login with your new password."}


# =========================================================

# SKILL DATABASE

# =========================================================

SKILL_DATABASE = {

    "programming_languages": [

        "JavaScript",

        "TypeScript",

        "Java",

        "Python",

        "C++",

        "C#",

        "C",

        "PHP",

        "Ruby",

        "Go",

        "Kotlin",

        "Swift"

    ],

    "frontend": [

        "HTML",

        "CSS",

        "React.js",

        "Next.js",

        "Angular",

        "Vue.js",

        "Tailwind CSS",

        "Bootstrap"

    ],

    "backend": [

        "Node.js",

        "Express.js",

        "FastAPI",

        "Django",

        "Flask",

        "Spring Boot",

        "Laravel"

    ],

    "databases": [

        "MongoDB",

        "MySQL",

        "PostgreSQL",

        "SQLite",

        "Redis",

        "Oracle"

    ],

    "tools": [

        "Git",

        "GitHub",

        "Docker",

        "AWS",

        "Azure",

        "Firebase",

        "Postman"

    ],

    "other": [

        "REST API",

        "GraphQL",

        "Machine Learning",

        "Deep Learning",

        "Data Structures",

        "Algorithms",

        "SQL"

    ]

}

# =========================================================

# SKILL ALIASES

# =========================================================

SKILL_ALIASES = {

    "javascript": "JavaScript",

    "js": "JavaScript",

    "typescript": "TypeScript",

    "ts": "TypeScript",

    "java": "Java",

    "python": "Python",

    "c++": "C++",

    "cpp": "C++",

    "c#": "C#",

    "csharp": "C#",

    "html": "HTML",

    "html5": "HTML",

    "css": "CSS",

    "css3": "CSS",

    "react": "React.js",

    "react.js": "React.js",

    "reactjs": "React.js",

    "next": "Next.js",

    "next.js": "Next.js",

    "nextjs": "Next.js",

    "node": "Node.js",

    "node.js": "Node.js",

    "nodejs": "Node.js",

    "express": "Express.js",

    "express.js": "Express.js",

    "expressjs": "Express.js",

    "mongodb": "MongoDB",

    "mongo db": "MongoDB",

    "mysql": "MySQL",

    "postgresql": "PostgreSQL",

    "postgres": "PostgreSQL",

    "sql": "SQL",

    "fastapi": "FastAPI",

    "django": "Django",

    "flask": "Flask",

    "spring boot": "Spring Boot",

    "springboot": "Spring Boot",

    "tailwind": "Tailwind CSS",

    "tailwind css": "Tailwind CSS",

    "bootstrap": "Bootstrap",

    "git": "Git",

    "github": "GitHub",

    "docker": "Docker",

    "aws": "AWS",

    "azure": "Azure",

    "firebase": "Firebase",

    "postman": "Postman",

    "rest api": "REST API",

    "restful api": "REST API",

    "graphql": "GraphQL",

    "machine learning": "Machine Learning",

    "ml": "Machine Learning",

    "deep learning": "Deep Learning",

    "dl": "Deep Learning",

    "data structures": "Data Structures",

    "data structure": "Data Structures",

    "algorithms": "Algorithms",

    "algorithm": "Algorithms"

}

# =========================================================

# FIND SKILLS

# =========================================================

def detect_skills(text):

    text_lower = text.lower()

    detected = []

    sorted_aliases = sorted(

        SKILL_ALIASES.items(),

        key=lambda item: len(item[0]),

        reverse=True

    )

    for alias, standard_name in sorted_aliases:

        if alias in [

            "c++",

            "c#",

            "csharp"

        ]:

            pattern = (

                r"(?<![a-zA-Z0-9])"

                + re.escape(alias)

                + r"(?![a-zA-Z0-9])"

            )

        else:

            pattern = (

                r"(?<![a-zA-Z0-9])"

                + re.escape(alias)

                + r"(?![a-zA-Z0-9])"

            )

        if re.search(pattern, text_lower):

            if standard_name not in detected:

                detected.append(

                    standard_name

                )

    return detected

# =========================================================

# DETECT SKILL CATEGORIES

# =========================================================

def categorize_skills(detected_skills):

    categories = {

        "programming_languages": [],

        "frontend": [],

        "backend": [],

        "databases": [],

        "tools": [],

        "other": []

    }

    for skill in detected_skills:

        found = False

        for category, skills in SKILL_DATABASE.items():

            if skill in skills:

                categories[category].append(

                    skill

                )

                found = True

                break

        if not found:

            categories["other"].append(

                skill

            )

    return categories

# =========================================================

# SECTION DETECTION

# =========================================================

def detect_sections(text):

    text_lower = text.lower()

    sections = {

        "summary": False,

        "education": False,

        "experience": False,

        "projects": False,

        "skills": False,

        "certifications": False

    }

    section_keywords = {

        "summary": [

            "summary",

            "professional summary",

            "profile",

            "objective",

            "career objective"

        ],

        "education": [

            "education",

            "academic",

            "qualification",

            "qualifications"

        ],

        "experience": [

            "experience",

            "work experience",

            "professional experience",

            "employment",

            "internship"

        ],

        "projects": [

            "projects",

            "project"

        ],

        "skills": [

            "skills",

            "technical skills",

            "technical skill",

            "technologies"

        ],

        "certifications": [

            "certifications",

            "certificates",

            "certification"

        ]

    }

    for section, keywords in section_keywords.items():

        for keyword in keywords:

            if keyword in text_lower:

                sections[section] = True

                break

    return sections

# =========================================================

# CONTACT INFORMATION

# =========================================================

def detect_contact_information(text):

    email_pattern = (

        r"[A-Za-z0-9._%+-]+"

        r"@[A-Za-z0-9.-]+"

        r"\.[A-Za-z]{2,}"

    )

    email_found = bool(

        re.search(

            email_pattern,

            text

        )

    )

    phone_pattern = (

        r"(?:\+91[\s-]?)?"

        r"[6-9]\d{9}"

    )

    phone_found = bool(

        re.search(

            phone_pattern,

            text

        )

    )

    linkedin_found = (

        "linkedin.com"

        in text.lower()

    )

    github_found = (

        "github.com"

        in text.lower()

    )

    return {

        "email": email_found,

        "phone": phone_found,

        "linkedin": linkedin_found,

        "github": github_found

    }

# =========================================================

# CALCULATE RESUME SCORE

# =========================================================

def calculate_score(

    detected_skills,

    sections,

    contact

):

    score = 0

    skill_count = len(

        detected_skills

    )

    if skill_count >= 10:

        score += 25

    elif skill_count >= 7:

        score += 22

    elif skill_count >= 5:

        score += 18

    elif skill_count >= 3:

        score += 12

    elif skill_count >= 1:

        score += 7

    section_count = sum(

        sections.values()

    )

    if section_count == 6:

        score += 30

    elif section_count == 5:

        score += 26

    elif section_count == 4:

        score += 22

    elif section_count == 3:

        score += 17

    elif section_count == 2:

        score += 12

    elif section_count == 1:

        score += 6

    if sections["projects"]:

        score += 15

    if sections["education"]:

        score += 10

    contact_count = sum(

        contact.values()

    )

    if contact_count == 4:

        score += 20

    elif contact_count == 3:

        score += 16

    elif contact_count == 2:

        score += 10

    elif contact_count == 1:

        score += 5

    return min(

        score,

        100

    )

# =========================================================

# STRENGTHS

# =========================================================

def generate_strengths(

    detected_skills,

    sections,

    contact

):

    strengths = []

    if len(detected_skills) >= 5:

        strengths.append(

            "Good number of technical skills detected."

        )

    if len(detected_skills) >= 10:

        strengths.append(

            "Strong technical skill coverage."

        )

    if sections["projects"]:

        strengths.append(

            "Projects section is present."

        )

    if sections["education"]:

        strengths.append(

            "Education section is present."

        )

    if sections["experience"]:

        strengths.append(

            "Experience section is present."

        )

    if sections["skills"]:

        strengths.append(

            "Dedicated skills section is present."

        )

    if contact["email"] and contact["phone"]:

        strengths.append(

            "Basic contact information is available."

        )

    if contact["linkedin"]:

        strengths.append(

            "LinkedIn profile is included."

        )

    if contact["github"]:

        strengths.append(

            "GitHub profile is included."

        )

    if not strengths:

        strengths.append(

            "Resume text was successfully extracted."

        )

    return strengths

# =========================================================

# IMPROVEMENTS

# =========================================================

def generate_improvements(

    detected_skills,

    sections,

    contact

):

    improvements = []

    if not sections["summary"]:

        improvements.append(

            "Add a clear professional summary."

        )

    if not sections["experience"]:

        improvements.append(

            "Add relevant experience or internship details if available."

        )

    if not sections["projects"]:

        improvements.append(

            "Add relevant projects with measurable outcomes."

        )

    if not sections["certifications"]:

        improvements.append(

            "Consider adding relevant certifications."

        )

    if len(detected_skills) < 5:

        improvements.append(

            "Add more relevant technical skills."

        )

    if not contact["linkedin"]:

        improvements.append(

            "Add your LinkedIn profile."

        )

    if not contact["github"]:

        improvements.append(

            "Add your GitHub profile if you have one."

        )

    return improvements

# =========================================================

# PDF TEXT EXTRACTION

# =========================================================

def _ocr_page(image):

    """Run OCR with light preprocessing for image-based resume PDFs."""

    if not OCR_AVAILABLE or pytesseract is None:

        return ""

    try:

        # First pass: normal image. This preserves small resume text well.

        text = pytesseract.image_to_string(image, config="--psm 6")

        if text and len(text.strip()) >= 20:

            return text

        # Second pass: grayscale + autocontrast for faint/light PDFs.

        from PIL import ImageOps, ImageFilter

        gray = ImageOps.grayscale(image)

        gray = ImageOps.autocontrast(gray)

        gray = gray.filter(ImageFilter.SHARPEN)

        return pytesseract.image_to_string(gray, config="--psm 6")

    except Exception as e:

        print(f"Tesseract OCR failed on page: {e}")

        return ""

def extract_text_from_pdf(file_content: bytes) -> str:

    """Extract selectable PDF text first; fall back to OCR for scanned/image PDFs."""

    # 1. pdfplumber

    try:

        parts = []

        with pdfplumber.open(io.BytesIO(file_content)) as pdf:

            for page in pdf.pages:

                text = page.extract_text(x_tolerance=1.5, y_tolerance=3) or ""

                if text.strip():

                    parts.append(text)

        result = "\n".join(parts).strip()

        if result:

            return result

    except Exception as e:

        print(f"pdfplumber failed: {e}")

    # 2. PyMuPDF

    try:

        parts = []

        with fitz.open(stream=file_content, filetype="pdf") as doc:

            for page in doc:

                text = page.get_text("text") or ""

                if text.strip():

                    parts.append(text)

        result = "\n".join(parts).strip()

        if result:

            return result

    except Exception as e:

        print(f"PyMuPDF failed: {e}")

    # 3. pypdf

    try:

        reader = PdfReader(io.BytesIO(file_content))

        parts = []

        for page in reader.pages:

            text = page.extract_text() or ""

            if text.strip():

                parts.append(text)

        result = "\n".join(parts).strip()

        if result:

            return result

    except Exception as e:

        print(f"pypdf failed: {e}")

    # 4. OCR fallback for Canva/image/browser-rendered PDFs

    if OCR_AVAILABLE and pytesseract is not None:

        try:

            parts = []

            with fitz.open(stream=file_content, filetype="pdf") as doc:

                for page_number, page in enumerate(doc, start=1):

                    # 220 DPI is a good balance for resume OCR speed/accuracy.

                    pix = page.get_pixmap(dpi=220, alpha=False)

                    image = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)

                    text = _ocr_page(image)

                    if text.strip():

                        parts.append(text)

                    print(f"OCR page {page_number}: {len(text.strip())} chars")

            result = "\n".join(parts).strip()

            if result:

                return result

        except Exception as e:

            print(f"OCR fallback failed: {e}")

    else:

        print("OCR unavailable. Install pytesseract and Tesseract OCR.")

    return ""

# =========================================================

# ANALYZE RESUME API

# =========================================================

@app.post("/api/analyze-resume")

async def analyze_resume(

    file: UploadFile = File(...),

    user_id: str = Form(None)

):

    # Validate user

    if not user_id:

        return {

            "success": False,

            "message": "User ID is required. Please login again."

        }

    # Validate file

    if file.content_type != "application/pdf":

        return {

            "success": False,

            "message": "Only PDF files are allowed."

        }

    # Read file

    file_content = await file.read()

    # Extract text using multiple PDF readers and OCR fallback

    try:

        extracted_text = extract_text_from_pdf(file_content)

    except Exception as e:

        return {

            "success": False,

            "message": f"Unable to read PDF: {str(e)}"

        }

    # Empty PDF check

    if not extracted_text.strip():

        return {

            "success": False,

            "message": (

                "No readable text was found. The PDF may be image-based/scanned. Install Tesseract OCR or upload a text-based PDF."

            )

        }

    # =====================================================

    # ANALYSIS

    # =====================================================

    detected_skills = detect_skills(

        extracted_text

    )

    skill_categories = categorize_skills(

        detected_skills

    )

    sections = detect_sections(

        extracted_text

    )

    contact = detect_contact_information(

        extracted_text

    )

    score = calculate_score(

        detected_skills,

        sections,

        contact

    )

    strengths = generate_strengths(

        detected_skills,

        sections,

        contact

    )

    improvements = generate_improvements(

        detected_skills,

        sections,

        contact

    )

    # =====================================================

    # SAVE ANALYSIS TO MONGODB

    # =====================================================

    analysis_document = {

        "user_id": user_id,

        "filename": file.filename,

        "score": score,

        "skills": detected_skills,

        "skill_count": len(

            detected_skills

        ),

        "skill_categories": skill_categories,

        "sections": sections,

        "contact": contact,

        "strengths": strengths,

        "improvements": improvements,

        "text": extracted_text

    }

    result = resume_analyses_collection.insert_one(

        analysis_document

    )

    # =====================================================

    # FINAL RESPONSE

    # =====================================================

    return {

        "success": True,

        "analysis_id": str(

            result.inserted_id

        ),

        "user_id": user_id,

        "filename": file.filename,

        "score": score,

        "skills": detected_skills,

        "skill_count": len(

            detected_skills

        ),

        "skill_categories": skill_categories,

        "sections": sections,

        "contact": contact,

        "strengths": strengths,

        "improvements": improvements,

        "text": extracted_text

    }

# =========================================================

# RESUME ANALYSIS HISTORY

# =========================================================

@app.get("/api/resume-history/{user_id}")

def get_resume_history(user_id: str):

    try:

        analyses = resume_analyses_collection.find(

            {

                "user_id": user_id

            }

        ).sort(

            "_id",

            -1

        )

        history = []

        for analysis in analyses:

            history.append({

                "id": str(

                    analysis["_id"]

                ),

                "filename": analysis.get(

                    "filename",

                    ""

                ),

                "score": analysis.get(

                    "score",

                    0

                ),

                "skill_count": analysis.get(

                    "skill_count",

                    0

                ),

                "skills": analysis.get(

                    "skills",

                    []

                ),

                "sections": analysis.get(

                    "sections",

                    {}

                ),

                "contact": analysis.get(

                    "contact",

                    {}

                ),

                "strengths": analysis.get(

                    "strengths",

                    []

                ),

                "improvements": analysis.get(

                    "improvements",

                    []

                ),

                "text": analysis.get(

                    "text",

                    ""

                )

            })

        return {

            "success": True,

            "count": len(history),

            "history": history

        }

    except Exception as e:

        return {

            "success": False,

            "message": (

                f"Unable to fetch resume history: {str(e)}"

            )

        }

# =========================================================

# JOB DESCRIPTION MATCHER

# =========================================================

@app.post("/api/match-job")

async def match_job(data: dict):

    resume_text = data.get(

        "resume_text",

        ""

    )

    job_description = data.get(

        "job_description",

        ""

    )

    # IMPORTANT:

    # Frontend must send logged-in user's ID

    user_id = data.get(

        "user_id"

    )

    # =====================================================

    # VALIDATION

    # =====================================================

    if not resume_text.strip():

        return {

            "success": False,

            "message": "Resume text is required."

        }

    if not job_description.strip():

        return {

            "success": False,

            "message": "Job description is required."

        }

    if not user_id:

        return {

            "success": False,

            "message": "User ID is required. Please login again."

        }

    # =====================================================

    # DETECT SKILLS

    # =====================================================

    resume_skills = detect_skills(

        resume_text

    )

    job_skills = detect_skills(

        job_description

    )

    # =====================================================

    # SKILL MAPS

    # =====================================================

    resume_skill_map = {

        skill.lower(): skill

        for skill in resume_skills

    }

    job_skill_map = {

        skill.lower(): skill

        for skill in job_skills

    }

    # =====================================================

    # MATCHED SKILLS

    # =====================================================

    matched_skills = []

    for skill in job_skill_map:

        if skill in resume_skill_map:

            matched_skills.append(

                resume_skill_map[skill]

            )

    # =====================================================

    # MISSING SKILLS

    # =====================================================

    missing_skills = []

    for skill in job_skill_map:

        if skill not in resume_skill_map:

            missing_skills.append(

                job_skill_map[skill]

            )

    # =====================================================

    # SKILL MATCH

    # =====================================================

    total_job_skills = len(

        job_skills

    )

    if total_job_skills > 0:

        skill_match = round(

            (

                len(matched_skills)

                / total_job_skills

            )

            * 100

        )

    else:

        skill_match = 0

    # =====================================================

    # KEYWORD MATCH

    # =====================================================

    resume_words = set(

        re.findall(

            r"\b[a-zA-Z][a-zA-Z0-9+#.-]*\b",

            resume_text.lower()

        )

    )

    job_words = set(

        re.findall(

            r"\b[a-zA-Z][a-zA-Z0-9+#.-]*\b",

            job_description.lower()

        )

    )

    important_keywords = {

        word

        for word in job_words

        if len(word) >= 4

    }

    if important_keywords:

        matched_keywords = (

            important_keywords

            & resume_words

        )

        keyword_match = round(

            (

                len(matched_keywords)

                / len(important_keywords)

            )

            * 100

        )

    else:

        keyword_match = 0

    # =====================================================

    # OVERALL MATCH SCORE

    # =====================================================

    match_score = round(

        (skill_match * 0.7)

        +

        (keyword_match * 0.3)

    )

    # =====================================================

    # RECOMMENDATIONS

    # =====================================================

    recommendations = []

    if missing_skills:

        recommendations.append(

            "Consider adding or learning the missing skills: "

            + ", ".join(

                missing_skills[:5]

            )

        )

    if keyword_match < 60:

        recommendations.append(

            "Your resume has relatively low keyword overlap "

            "with this job description."

        )

    if skill_match >= 80:

        recommendations.append(

            "Your technical skills are strongly aligned "

            "with this job."

        )

    elif skill_match >= 60:

        recommendations.append(

            "Your resume has a good technical match, "

            "but some job-specific skills are missing."

        )

    else:

        recommendations.append(

            "Consider improving your skill alignment "

            "before applying."

        )

    # =====================================================

    # SAVE JD MATCH TO MONGODB

    # =====================================================

    match_document = {

        "user_id": user_id,

        "resume_text": resume_text,

        "job_description": job_description,

        "match_score": match_score,

        "skill_match": skill_match,

        "keyword_match": keyword_match,

        "resume_skills": resume_skills,

        "job_skills": job_skills,

        "matched_skills": matched_skills,

        "missing_skills": missing_skills,

        "recommendations": recommendations

    }

    result = jd_matches_collection.insert_one(

        match_document

    )

    # =====================================================

    # FINAL RESPONSE

    # =====================================================

    return {

        "success": True,

        "match_id": str(

            result.inserted_id

        ),

        "user_id": user_id,

        "match_score": match_score,

        "skill_match": skill_match,

        "keyword_match": keyword_match,

        "resume_skills": resume_skills,

        "job_skills": job_skills,

        "matched_skills": matched_skills,

        "missing_skills": missing_skills,

        "recommendations": recommendations

    }

# =========================================================

# JD MATCH HISTORY

# =========================================================

@app.get("/api/jd-match-history/{user_id}")

def get_jd_match_history(user_id: str):

    try:

        if not user_id:

            return {"success": False, "message": "User ID is required."}

        matches = jd_matches_collection.find({"user_id": user_id}).sort("_id", -1)

        history = []

        for match in matches:

            history.append({

                "id": str(match["_id"]),

                "match_score": match.get("match_score", 0),

                "skill_match": match.get("skill_match", 0),

                "keyword_match": match.get("keyword_match", 0),

                "matched_skills": match.get("matched_skills", []),

                "missing_skills": match.get("missing_skills", []),

                "recommendations": match.get("recommendations", []),

                "resume_skills": match.get("resume_skills", []),

                "job_skills": match.get("job_skills", []),

                "resume_text": match.get("resume_text", ""),

                "job_description": match.get("job_description", ""),

                "created_at": match.get("created_at")

            })

        return {

            "success": True,

            "count": len(history),

            "history": history

        }

    except Exception as e:

        return {

            "success": False,

            "message": f"Unable to fetch JD match history: {str(e)}"

        }

# =========================================================

# ATS CHECKER

# =========================================================

@app.post("/api/check-ats")

async def check_ats(

    file: UploadFile = File(...),

    user_id: str = Form(None)

):

    if not file.filename.lower().endswith(

        ".pdf"

    ):

        return {

            "success": False,

            "message": "Only PDF files are supported."

        }

    try:

        if not user_id:

            return {

                "success": False,

                "message": "User ID is required. Please login again."

            }

        contents = await file.read()

        text = extract_text_from_pdf(contents)

        if not text.strip():

            return {

                "success": False,

                "message": (

                    "Could not extract text from the resume. The PDF may be image-based/scanned. Install Tesseract OCR or upload a text-based PDF."

                )

            }

        # =================================================

        # DETECT RESUME INFORMATION

        # =================================================

        skills = detect_skills(

            text

        )

        sections = detect_sections(

            text

        )

        contact = detect_contact_information(

            text

        )

        # =================================================

        # ATS SCORE

        # =================================================

        score = calculate_score(

            skills,

            sections,

            contact

        )

        # =================================================

        # WORD COUNT

        # =================================================

        word_count = len(

            re.findall(

                r"\b[a-zA-Z][a-zA-Z0-9+#.-]*\b",

                text

            )

        )

        # =================================================

        # SECTION COUNT

        # =================================================

        section_count = sum(

            1

            for value in sections.values()

            if value

        )

        # =================================================

        # CONTACT COUNT

        # =================================================

        contact_count = sum(

            1

            for value in contact.values()

            if value

        )

        # =================================================

        # RECOMMENDATIONS

        # =================================================

        recommendations = []

        if word_count < 300:

            recommendations.append(

                "Your resume contains relatively little text. "

                "Consider adding more relevant project or experience details."

            )

        if word_count > 1200:

            recommendations.append(

                "Your resume may be too long. "

                "Consider keeping the content concise and relevant."

            )

        if section_count < 4:

            recommendations.append(

                "Some important resume sections appear to be missing."

            )

        if contact_count < 3:

            recommendations.append(

                "Add complete contact information such as email, phone, "

                "LinkedIn, or GitHub."

            )

        if len(skills) < 5:

            recommendations.append(

                "Add more relevant technical skills that match your target jobs."

            )

        # =================================================

        # ATS STATUS

        # =================================================

        if score >= 80:

            ats_status = "Excellent"

        elif score >= 65:

            ats_status = "Good"

        elif score >= 50:

            ats_status = "Needs Improvement"

        else:

            ats_status = "Poor"

        # =================================================

        # SAVE ATS ANALYSIS TO MONGODB

        # =================================================

        ats_document = {

            "user_id": user_id,

            "filename": file.filename,

            "ats_score": score,

            "status": ats_status,

            "word_count": word_count,

            "skill_count": len(skills),

            "section_count": section_count,

            "contact_count": contact_count,

            "skills": skills,

            "sections": sections,

            "contact": contact,

            "recommendations": recommendations,

            "created_at": datetime.utcnow()

        }

        ats_result = ats_analyses_collection.insert_one(ats_document)

        # =================================================

        # FINAL RESPONSE

        # =================================================

        return {

            "success": True,

            "analysis_id": str(ats_result.inserted_id),

            "user_id": user_id,

            "filename": file.filename,

            "ats_score": score,

            "status": ats_status,

            "word_count": word_count,

            "skill_count": len(skills),

            "section_count": section_count,

            "contact_count": contact_count,

            "skills": skills,

            "sections": sections,

            "contact": contact,

            "recommendations": recommendations

        }

    except Exception as e:

        return {

            "success": False,

            "message": (

                f"Error processing resume: {str(e)}"

            )

        }

# =========================================================

# ATS ANALYSIS HISTORY

# =========================================================

@app.get("/api/ats-history/{user_id}")

def get_ats_history(user_id: str):

    try:

        if not user_id:

            return {"success": False, "message": "User ID is required."}

        analyses = ats_analyses_collection.find({"user_id": user_id}).sort("_id", -1)

        history = []

        for analysis in analyses:

            history.append({

                "id": str(analysis["_id"]),

                "filename": analysis.get("filename", ""),

                "ats_score": analysis.get("ats_score", 0),

                "status": analysis.get("status", ""),

                "word_count": analysis.get("word_count", 0),

                "skill_count": analysis.get("skill_count", 0),

                "section_count": analysis.get("section_count", 0),

                "contact_count": analysis.get("contact_count", 0),

                "skills": analysis.get("skills", []),

                "sections": analysis.get("sections", {}),

                "contact": analysis.get("contact", {}),

                "recommendations": analysis.get("recommendations", []),

                "created_at": analysis.get("created_at")

            })

        return {"success": True, "count": len(history), "history": history}

    except Exception as e:

        print(f"ATS history error: {e}")

        return {"success": False, "message": f"Unable to fetch ATS history: {str(e)}"}

# =========================================================

# DASHBOARD STATS

# =========================================================

@app.get("/api/dashboard-stats/{user_id}")

def get_dashboard_stats(user_id: str):

    """Return dashboard statistics for the logged-in user."""

    try:

        if not user_id:

            return {"success": False, "message": "User ID is required."}

        try:

            user = users_collection.find_one({"_id": ObjectId(user_id)})

        except Exception:

            user = None

        if not user:

            return {"success": False, "message": "User not found."}

        resume_records = list(

            resume_analyses_collection.find({"user_id": user_id}).sort("_id", -1)

        )

        resume_scores = [

            r.get("score") for r in resume_records

            if isinstance(r.get("score"), (int, float))

        ]

        resume_count = len(resume_records)

        average_resume_score = round(sum(resume_scores) / len(resume_scores)) if resume_scores else 0

        latest_resume = resume_records[0] if resume_records else None

        ats_records = list(

            ats_analyses_collection.find({"user_id": user_id}).sort("_id", -1)

        )

        ats_scores = [

            r.get("ats_score") for r in ats_records

            if isinstance(r.get("ats_score"), (int, float))

        ]

        ats_count = len(ats_records)

        average_ats_score = round(sum(ats_scores) / len(ats_scores)) if ats_scores else 0

        latest_ats = ats_records[0] if ats_records else None

        jd_records = list(

            jd_matches_collection.find({"user_id": user_id}).sort("_id", -1)

        )

        jd_scores = [

            r.get("match_score") for r in jd_records

            if isinstance(r.get("match_score"), (int, float))

        ]

        jd_count = len(jd_records)

        average_match_score = round(sum(jd_scores) / len(jd_scores)) if jd_scores else 0

        latest_jd = jd_records[0] if jd_records else None

        latest_resume_score = latest_resume.get("score") if latest_resume else None

        latest_ats_score = latest_ats.get("ats_score") if latest_ats else None

        latest_match_score = latest_jd.get("match_score") if latest_jd else None

        matched_skills = latest_jd.get("matched_skills", []) if latest_jd else []

        missing_skills = latest_jd.get("missing_skills", []) if latest_jd else []

        valid_scores = [

            score for score in [

                latest_resume_score, latest_ats_score, latest_match_score

            ] if isinstance(score, (int, float))

        ]

        career_readiness = round(sum(valid_scores) / len(valid_scores)) if valid_scores else 0

        return {

            "success": True,

            "stats": {

                "resume_count": resume_count,

                "ats_count": ats_count,

                "jd_match_count": jd_count,

                "average_resume_score": average_resume_score,

                "average_ats_score": average_ats_score,

                "average_match_score": average_match_score,

                "latest_resume_score": latest_resume_score,

                "latest_ats_score": latest_ats_score,

                "latest_match_score": latest_match_score,

                "skills_matched": len(matched_skills),

                "skills_missing": len(missing_skills),

                "career_readiness": career_readiness

            }

        }

    except Exception as e:

        print(f"Dashboard stats error: {e}")

        return {

            "success": False,

            "message": f"Unable to load dashboard data: {str(e)}"

        }