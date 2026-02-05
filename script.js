
// User Roles and Permissions

const USER_ROLES = {
    DOCTOR: 'doctor',
    NURSE: 'nurse',
    ADMIN: 'admin',
    PATIENT: 'patient'
};

const PERMISSIONS = {
    VIEW_PATIENT_RECORDS: 'view_records', // Permission to view patient records
    WRITE_PATIENT_RECORDS: 'write_records', // Modify patient records
    DELETE_PATIENT_RECORDS: 'delete_records', // Delete patient records
    MANAGE_USERS: 'manage_users' // Manage user accounts

};

const ROLE_PERMISSIONS = {
    [USER_ROLES.DOCTOR]: [
        PERMISSIONS.VIEW_PATIENT_RECORDS,
        PERMISSIONS.WRITE_PATIENT_RECORDS,
        PERMISSIONS.DELETE_PATIENT_RECORDS
    ],
    [USER_ROLES.NURSE]: [
        PERMISSIONS.VIEW_PATIENT_RECORDS,
        PERMISSIONS.WRITE_PATIENT_RECORDS
    ],
    [USER_ROLES.ADMIN]: [
        PERMISSIONS.VIEW_PATIENT_RECORDS,
        PERMISSIONS.MANAGE_USERS
    ],
    [USER_ROLES.PATIENT]: [
        PERMISSIONS.VIEW_PATIENT_RECORDS
    ]
};

class UserManager {
    constructor() {
        this.users = new Map();
        this.sessions = new Map()
        }
    };

const user = {
    userId: userId,
    name: name,
    role: role,
    password: password,
    active: CSSPositionTryDescritor,
    createdAt: new Date()
};
