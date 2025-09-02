import os
import datetime
import platform
from crypto_utils import ensure_keypair, PUBLIC_KEY_FILE
from files_utils import collect_files, sha256_file, secure_wipe_file
from certificate_utils import build_certificate, write_certificate_files


# High level function to run wipe and produce certificate (called by GUI)
def wipe_folder_and_certify(folder_path: str, operator_id: str, passes: int = 3, output_dir: str = "output"):
    """
    WARNING: Destructive. Overwrites and deletes files in folder_path.
    Returns paths to signed JSON and PDF certificate.
    """
    private_key, public_key = ensure_keypair()
    files, total_size, hidden_files = collect_files(folder_path)
    start_time = datetime.datetime.utcnow()
    # compute hashes BEFORE overwriting
    file_hashes = []
    for fpath in files:
        try:
            h = sha256_file(fpath)
            file_hashes.append({"path": fpath, "sha256": h, "size": os.path.getsize(fpath)})
        except Exception as e:
            file_hashes.append({"path": fpath, "sha256": None, "size": None, "error": str(e)})

    # perform secure wipe
    wiped_count = 0
    for fpath in files:
        try:
            secure_wipe_file(fpath, passes=passes)
            wiped_count += 1
        except Exception as e:
            # continue on error, record in audit
            pass

    # remove empty dirs
    for root, dirs, _ in os.walk(folder_path, topdown=False):
        for d in dirs:
            dir_path = os.path.join(root, d)
            try:
                if not os.listdir(dir_path):
                    os.rmdir(dir_path)
            except Exception:
                pass

    end_time = datetime.datetime.utcnow()
    duration = (end_time - start_time).total_seconds()

    # Build certificate data
    device_info = {
        "device_id": os.uname().nodename if hasattr(os, "uname") else os.getenv("COMPUTERNAME", "unknown"),
        "device_model": os.uname().machine if hasattr(os, "uname") else "unknown",
        "device_manufacturer": os.uname().sysname if hasattr(os, "uname") else "unknown",
        "operating_system": os.name,
        "os_version": repr(os.sys.platform),
        "device_type": "PC",
        "storage_type": "SSD/HDD (folder-level wipe)"
    }

    wipe_details = {
        "wipe_method": f"NIST SP 800-88: {passes}-pass overwrite (file-level).",
        "wipe_level": "Folder/Files Full Wipe",
        "data_areas_wiped": {
            "main_storage": f"{round(total_size/1e9, 4)}GB wiped",
            "hidden_storage_areas": f"{hidden_files}",
            "partition_information": "N/A (folder-level)",
            "non_volatile_memory": "N/A"
        },
        "data_wipe_duration_seconds": duration,
        "total_wiped_data_volume_bytes": total_size,
        "wiped_file_count": wiped_count,
        "wiped_files_snapshot": file_hashes
    }

    crypto_info = {
        "digital_signature": None,  # will be filled after signing
        "public_key_certificate_path": os.path.abspath(PUBLIC_KEY_FILE),
        "signature_algorithm": "RSA-3072|SHA256",
    }

    user_info = {
        "operator": operator_id,
        "timestamp_utc_start": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "timestamp_utc_end": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    process_details = {
        "application": "SecureErase Demo",
        "version": "v_demo_1.0",
        "platform": platform_info_simple()
    }

    third_party = {"verified_by": "N/A"}
    disclaimer_terms = {"disclaimer": "Demo software. Use responsibly. No warranty."}
    audit_trail = {"operator": operator_id, "files_attempted": len(files), "files_wiped": wiped_count}
    signature_auth = {"issuer_organization": "SecureWipe Certification Authority (Demo)"}
    blockchain_id = {}

    cert = build_certificate(device_info, wipe_details, crypto_info, user_info, process_details,
                             third_party, disclaimer_terms, audit_trail, signature_auth, blockchain_id)

    # write & sign
    # If output_dir is a dict, use as output_dirs; else, use legacy behavior
    if isinstance(output_dir, dict):
        output_dirs = {k: os.path.abspath(v) for k, v in output_dir.items()}
    else:
        output_dirs = {"json": os.path.abspath(output_dir), "pdf": os.path.abspath(output_dir)}
    signed_json_path, pdf_path = write_certificate_files(cert, output_dirs, private_key, public_key)
    return signed_json_path, pdf_path

def platform_info_simple():
    try:
        import platform as _p

        return {
            "system": _p.system(),
            "release": _p.release(),
            "version": _p.version(),
            "machine": _p.machine(),
            "node": _p.node(),
        }
    except Exception:
        return {}
