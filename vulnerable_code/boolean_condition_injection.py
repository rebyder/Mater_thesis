#S
import sqlite3


def get_patient_record(patient_id: str) -> None:
    """Fetch a patient record by patient_id from an SQLite database.

    SQL injection vulnerability:
    - `patient_id` is directly concatenated into the WHERE condition.
    - Attackers can inject expressions like `1 OR 1=1` to bypass checks.
    """
    conn = sqlite3.connect("hospital.db")
    try:
        cursor = conn.cursor()

        # VULNERABLE: `patient_id` used directly in numeric condition
        query = "SELECT id, full_name, diagnosis FROM patients WHERE id = " + patient_id
        print(f"[DEBUG] Executing: {query}")
        cursor.execute(query)
        row = cursor.fetchone()

        if row:
            print("Patient:", row)
        else:
            print("No patient found with that ID.")
    finally:
        conn.close()


if __name__ == "__main__":
    user_input = input("Enter patient ID: ")
    get_patient_record(user_input)
