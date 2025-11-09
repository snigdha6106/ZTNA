# 🛡️ ZTNAPro Demo: A Zero Trust Network Architecture Simulator

This project is a web-based application built with Flask and MongoDB to demonstrate the core principles of a **Zero Trust Network Architecture (ZTNA)**.

It simulates a corporate environment where user access to resources is not granted by default (like with a traditional VPN). Instead, every request is authenticated and authorized against a dynamic, context-aware policy engine.



## 🚀 Key Features Demonstrated

* **Strong Identity:** Enforces mandatory **Multi-Factor Authentication (MFA)** for all user registrations and logins using TOTP (Time-based One-time Password).
* **Context-Aware Access:** The policy engine evaluates not just the user's role but also the *context* of the request, such as **IP address** and **time of day**.
* **Role-Based Access Control (RBAC):** Users are assigned roles (e.g., 'Finance', 'HR', 'Admin'), and the policy engine grants or denies access based on granular rules.
* **Dynamic Policy Management:** A secure `/admin` panel allows an administrator to add or delete access policies in real-time, with changes taking effect immediately.
* **Real-Time Auditing:** A "Policy Decision Log" on the user's dashboard shows every `GRANTED` or `DENIED` decision and the reason why.
* **Secure Session Management:** Uses **JSON Web Tokens (JWTs)** to manage authenticated sessions.

## 🏛️ Architecture

The application uses a classic 3-tier architecture:

1.  **Client Tier (Frontend):** A browser-based interface for registration, login, the user dashboard, and the admin panel.
2.  **Application Tier (Backend / PEP):** A **Flask** server (`app.py`) acts as the **Policy Enforcement Point (PEP)**. It handles all authentication, MFA logic, JWT issuance, and policy evaluation.
3.  **Data Tier (Database / PDP):** A **MongoDB** database acts as the **Policy Decision Point (PDP)** and identity store.
    * `users` **collection:** Stores user identity, hashed passwords (bcrypt), and MFA secrets.
    * `policies` **collection:** Stores all access rules (role, resource, IP, time).

## 🛠️ Technology Stack

* **Backend:** Python, Flask
* **Database:** MongoDB (with PyMongo)
* **Authentication:** Flask-Bcrypt (for password hashing), pyotp & qrcode (for MFA/TOTP), PyJWT (for JSON Web Tokens)
* **Frontend:** HTML / CSS / JavaScript (served by Flask)

## 🏁 Getting Started

### Prerequisites

* Python 3.10+
* A running MongoDB instance (e.g., MongoDB Community Edition or Atlas)
* An authenticator app (e.g., Google Authenticator, Authy) on your phone

### Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/ZTNAPro-Demo.git](https://github.com/your-username/ZTNAPro-Demo.git)
    cd ZTNAPro-Demo
    ```

2.  **Create a virtual environment and activate it:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install the required libraries:**
    ```bash
    pip install -r requirements.txt
    ```
    *(This will install `Flask`, `pymongo`, `flask-bcrypt`, `pyotp`, `qrcode`, `jwt`, etc.)*

4.  **Configure the application:**
    Open `app.py` and update the MongoDB connection string to point to your database:
    ```python
    # Near the top of app.py
    app.config["MONGO_URI"] = "mongodb://localhost:27017/ztna_professional_db"
    ```

5.  **Run the application:**
    ```bash
    flask run
    ```
    The application will be running at `http://127.0.0.1:5000`.

## 🧪 How to Demo the ZTNA Features

Follow these scenarios just like in the video to test the Zero Trust policies.

### Scenario 1: Context-Aware Denial (Time Policy)
1.  **Register a 'Finance' user:**
    * Go to `http://127.0.0.1:5000` and click "Register".
    * Create a user (e.g., `snigdha_6106`) and select the **Finance** role.
    * Scan the QR code with your authenticator app and complete the MFA registration.
2.  **Login as the 'Finance' user:**
    * Log in with your new user's credentials and the 6-digit MFA code.
3.  **Test Access (DENIED):**
    * *Before you test*, make sure the default policy in your `policies` collection restricts access (e.g., `09:00` to `17:00`).
    * If you are testing *outside* these hours, click the **"Access Finance DB"** button.
    * Observe the "Policy Decision Log". Access will be **`DENIED`** with a reason related to the time restriction.
4.  **Test Access (RBAC DENIED):**
    * Click the **"Access HR Portal"** button.
    * Observe the log. Access will be **`DENIED`** because the 'Finance' role does not have permission for this resource.

### Scenario 2: Role-Based Access (HR User)
1.  **Register an 'HR' user:**
    * Log out and register a new user (e.g., `somesh`) with the **HR** role.
2.  **Login as the 'HR' user:**
    * Log in with the 'HR' user's credentials and MFA code.
3.  **Test Access (RBAC DENIED):**
    * Click the **"Access Finance DB"** button.
    * Observe the log. Access will be **`DENIED`**.
4.  **Test Access (RBAC GRANTED):**
    * Click the **"Access HR Portal"** button.
    * Observe the log. Access will be **`GRANTED`**.

### Scenario 3: Dynamic Policy Administration
1.  **Register an 'Admin' user:**
    * Log out and register a new user (e.g., `admin1`) with the **Admin** role.
2.  **Login as 'Admin' and add a policy:**
    * Log in as `admin1`.
    * Click the **"Admin Panel"** button.
    * In the "Add New Policy" form, enter:
        * Role: `Finance`
        * Resource: `hrPortal`
    * Click **"Add Policy"**. You will see the new policy appear in the "Current Access Policies" table.
3.  **Verify the new policy:**
    * Log out of the 'Admin' account.
    * Log back in as your 'Finance' user (`snigdha_6106`).
    * Click the **"Access HR Portal"** button.
    * Observe the log. Access will now be **`GRANTED`**, proving the policy was updated and enforced in real-time.
