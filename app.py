import os
import bcrypt
import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime, text
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, scoped_session
from sqlalchemy.sql import func
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database setup
DATABASE_URL = "postgresql://file_app_user:secure_password@postgresql:5432/file_app"
engine = create_engine(DATABASE_URL)
Base = declarative_base()
session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)
st.set_page_config(page_title="Alfa File Hub", layout="wide")

# Models
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)  # Store passwords as hashed byte strings
    role = Column(String)
    files = relationship("File", back_populates="user")

class File(Base):
    __tablename__ = 'files'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    path = Column(String)
    deleted = Column(Boolean, default=False)
    enabled = Column(Boolean, default=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship("User", back_populates="files")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

Base.metadata.create_all(engine)

# Utility functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed_password, plain_password):
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

def add_user(username, password, role):
    with Session() as session:
        if not username or not password:
            st.error("Username and password cannot be empty.")
            return
        if session.query(User).filter_by(username=username).first():
            st.error("Username already exists. Please choose a different username.")
            return
        hashed_password = hash_password(password)
        new_user = User(username=username, password=hashed_password.decode('utf-8'), role=role)
        session.add(new_user)
        session.commit()
        st.success("User added successfully.")

def authenticate(username, password):
    with Session() as session:
        user = session.query(User).filter_by(username=username).first()
        if user and check_password(user.password, password):
            return user
        return None

def add_file(file, user_id):
    with Session() as session:
        new_file = File(name=file.name, path=f"uploads/{user_id}/{file.name}", user_id=user_id)
        session.add(new_file)
        session.commit()

def create_default_admin():
    with Session() as session:
        if not session.query(User).filter_by(username='admin').first():
            add_user('admin', 'pass', 'admin')
            st.info("Default admin user created: username=admin, password=pass")

create_default_admin()

# Ensure 'uploads' directory exists
os.makedirs('uploads', exist_ok=True)

# Read allowed extensions from environment variable
allowed_extensions = os.getenv('ALLOWED_EXTENSIONS').split(',')

# Streamlit interface
st.title("Alfa File Hub")

# Sidebar login and user info
if 'user_info' not in st.session_state:
    st.session_state['user_info'] = {'username': None, 'role': None, 'user_id': None}

user_info = st.session_state['user_info']

if user_info['username'] is None:
    st.sidebar.header("Login")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Login"):
        user = authenticate(username, password)
        if user:
            st.session_state['user_info'] = {'username': username, 'role': user.role, 'user_id': user.id}
            st.experimental_rerun()
        else:
            st.error("Invalid credentials")
else:
    st.sidebar.write(f"Logged in as: **{user_info['username']}**")
    role = user_info['role']
    user_id = user_info['user_id']

    if role == 'admin':
        st.sidebar.header("Admin Panel")
        new_username = st.sidebar.text_input("New Username")
        new_password = st.sidebar.text_input("New Password", type="password")
        new_role = st.sidebar.selectbox("Role", ["admin", "user", "readonly"])
        if st.sidebar.button("Add User"):
            add_user(new_username, new_password, new_role)

    if role != 'readonly':
        uploaded_files = st.file_uploader("Select files to upload", accept_multiple_files=True)

        if st.button("Upload Files"):
            if uploaded_files:
                user_upload_dir = f"uploads/{user_id}"
                os.makedirs(user_upload_dir, exist_ok=True)

                reuploaded_any_file = False  # Flag to check if any file was re-uploaded

                for uploaded_file in uploaded_files:
                    file_extension = uploaded_file.name.split(".")[-1].lower()
                    if file_extension not in allowed_extensions:
                        st.warning(f"File {uploaded_file.name} has an unsupported file type.")
                        continue

                    file_path = f"{user_upload_dir}/{uploaded_file.name}"
                    file_record = Session().query(File).filter_by(name=uploaded_file.name, user_id=user_id).first()

                    if not file_record:
                        with open(file_path, "wb") as f:
                            f.write(uploaded_file.getbuffer())
                        add_file(uploaded_file, user_id)
                        st.success(f"File {uploaded_file.name} uploaded successfully.")
                    elif file_record.deleted:
                        # If the file is marked as deleted, allow re-upload and update the record
                        with open(file_path, "wb") as f:
                            f.write(uploaded_file.getbuffer())
                        file_record.deleted = False
                        Session().commit()
                        reuploaded_any_file = True  # Set the flag to True
                    else:
                        st.warning(f"File {uploaded_file.name} already exists.")

                # Show the success message for re-uploaded files only once
                if reuploaded_any_file:
                    st.success("Files re-uploaded successfully")
            else:
                st.warning("No files selected for upload.")

# Function to load and update data
def load_data():
    # Get role and user_id from session state
    role = st.session_state['user_info']['role']
    user_id = st.session_state['user_info']['user_id']

    # Construct the base query
    query = Session().query(File)

    # Apply filters based on user role
    if role == 'admin' or role == 'readonly':
        # Admin and readonly-specific filters
        if search_query:
            query = query.filter(File.name.contains(search_query))
        if role == 'admin' and user_filter != "All":
            user_id_filter = Session().query(User).filter_by(username=user_filter).first().id
            query = query.filter(File.user_id == user_id_filter)
        if enabled_filter == "Enabled":
            query = query.filter(File.enabled == True)
        elif enabled_filter == "Disabled":
            query = query.filter(File.enabled == False)
        if date_from:
            query = query.filter(File.created_at >= date_from)
        if date_to:
            date_to_end_of_day = datetime.combine(date_to, datetime.max.time())
            query = query.filter(File.created_at <= date_to_end_of_day)
    else:
        # User-specific filters (no user filter)
        query = query.filter(File.user_id == user_id)
        if search_query:
            query = query.filter(File.name.contains(search_query))
        if enabled_filter == "Enabled":
            query = query.filter(File.enabled == True)
        elif enabled_filter == "Disabled":
            query = query.filter(File.enabled == False)
        if date_from:
            query = query.filter(File.created_at >= date_from)
        if date_to:
            date_to_end_of_day = datetime.combine(date_to, datetime.max.time())
            query = query.filter(File.created_at <= date_to_end_of_day)

    # Exclude records where Deleted = True
    query = query.filter(File.deleted == False)

    files = query.all()

    if role == 'readonly':
        if files:
            # Display files in a table for read-only users
            file_data = [
                {
                    "Enabled": file.enabled,
                    "ID": file.id,
                    "Name": file.name,
                    "User": file.user.username,
                    "Created At": file.created_at.strftime("%Y-%m-%d %H:%M:%S")
                }
                for file in files
            ]
            df = pd.DataFrame(file_data)
            st.dataframe(df, width=None, use_container_width=True, hide_index=True)
    else:
        if files:
            # Display files in a table for editable users
            file_data = [
                {
                    "Delete": file.deleted,
                    "Enabled": file.enabled,
                    "ID": file.id,
                    "Name": file.name,
                    "User": file.user.username,
                    "Created At": file.created_at.strftime("%Y-%m-%d %H:%M:%S")
                }
                for file in files
            ]
            df = pd.DataFrame(file_data)
            edited_df = st.data_editor(data=df,
                                    key="file_data", 
                                    hide_index=True,
                                    width=None,
                                    use_container_width=True,
                                    column_config={
                                        "ID": st.column_config.Column("ID", disabled=True),
                                        "Name": st.column_config.Column("Name", disabled=True),
                                        "User": st.column_config.Column("User", disabled=True),
                                        "Created At": st.column_config.Column("Created At", disabled=True)
                                    }
                                    )
            return edited_df


# Check if user is logged in
if user_info['username'] is None:
    st.warning("You need to log in first.")
else:
    # Load data based on user role
    if 'role' in user_info:
        role = user_info['role']
        if role == 'admin':
            st.header("Manage Files")

            # Search filters with tracking for changes
            st.subheader("Search Filters")

            col1, col2, col3 = st.columns([4, 1, 1])
            col4, col5 = st.columns([1, 1])

            with col1:
                search_query = st.text_input("Search files", key="search_query", on_change=lambda: st.session_state.update({'filters_changed': True}))

            with col2:
                date_from = st.date_input("Date from", key="date_from", on_change=lambda: st.session_state.update({'filters_changed': True}))

            with col3:
                date_to = st.date_input("Date to", key="date_to", on_change=lambda: st.session_state.update({'filters_changed': True}))

            with col4:
                user_filter = st.selectbox("Filter by user", ["All"] + [user.username for user in Session().query(User).all()], key="user_filter", on_change=lambda: st.session_state.update({'filters_changed': True}))

            with col5:
                enabled_filter = st.selectbox("Enabled status", ["All", "Enabled", "Disabled"], key="enabled_filter", on_change=lambda: st.session_state.update({'filters_changed': True}))

        elif role == 'readonly':
            st.header("View All Files")

            # Read-only user-specific search filters
            st.subheader("Search Filters")

            col1, col2 = st.columns([4, 2])
            col3, col4 = st.columns([1, 1])

            with col1:
                search_query = st.text_input("Search files", key="search_query", on_change=lambda: st.session_state.update({'filters_changed': True}))

            with col2:
                date_from = st.date_input("Date from", key="date_from", on_change=lambda: st.session_state.update({'filters_changed': True}))
                date_to = st.date_input("Date to", key="date_to", on_change=lambda: st.session_state.update({'filters_changed': True}))

            with col3:
                st.write(" ")

            with col4:
                enabled_filter = st.selectbox("Enabled status", ["All", "Enabled", "Disabled"], key="enabled_filter", on_change=lambda: st.session_state.update({'filters_changed': True}))

        else:
            st.header("Manage Your Files")

            # User-specific search filters
            st.subheader("Search Filters")

            col1, col2 = st.columns([4, 2])
            col3, col4 = st.columns([1, 1])

            with col1:
                search_query = st.text_input("Search files", key="search_query", on_change=lambda: st.session_state.update({'filters_changed': True}))

            with col2:
                date_from = st.date_input("Date from", key="date_from", on_change=lambda: st.session_state.update({'filters_changed': True}))
                date_to = st.date_input("Date to", key="date_to", on_change=lambda: st.session_state.update({'filters_changed': True}))

            with col3:
                st.write(" ")

            with col4:
                enabled_filter = st.selectbox("Enabled status", ["All", "Enabled", "Disabled"], key="enabled_filter", on_change=lambda: st.session_state.update({'filters_changed': True}))

        edited_df = load_data()

        # Update database when "Update Database" button is clicked
        if role != 'readonly' and st.button("Update Database"):
            try:
                for index, row in edited_df.iterrows():
                    file_id = row['ID']
                    enabled = row.get('Enabled', False)  # Default to False if 'Enabled' is not found in the row
                    deleted = row.get('Delete', False)   # Default to False if 'Delete' is not found in the row
                    
                    # Fetch the corresponding File object from database
                    file_obj = Session().query(File).filter_by(id=file_id).first()
                    
                    if file_obj:
                        # Update the 'enabled' attribute based on the edited value
                        file_obj.enabled = enabled
                        
                        # Check if 'deleted' status is changed to True
                        if deleted:
                            # Delete file from app directory
                            if os.path.exists(file_obj.path):
                                os.remove(file_obj.path)
                            # Update 'deleted' status in database
                            file_obj.deleted = True

                Session().commit()
                st.success("Database updated successfully")
                st.experimental_rerun()

            except Exception as e:
                st.error(f"Error updating database: {str(e)}")

    if st.sidebar.button("Logout"):
        st.session_state['user_info'] = {'username': None, 'role': None, 'user_id': None}
        st.experimental_rerun()
