from strenum import StrEnum

# Only used for backwards compatability with kaos' competition config
class SubmissionStatus(StrEnum):
    Ok = 'OK'
    Dup = 'DUP'
    Own = 'OWN'
    Old = 'OLD'
    Inv = 'INV'
    Err = 'ERR'
