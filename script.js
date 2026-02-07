
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
   
    createUser(userId, name, role, password) {
        if (this.users.has(userId)) {
            console.log(`❌ User ${userId} already exists`);
            return false;
        }

        const user = {
            userId: userId,
            name: name,
            role: role,
            password: password,
            active: true,
            createdAt: new Date()
        };

        this.users.set(userId, user);
        console.log(`✅ User ${userId} created successfully`);
        return true;
    }

    login(userId, password) {
        const user = this.users.get(userId);
        if (!user || user.password !== password) {
            console.log('❌ Login failed for ${userId}');
            return null;
        }

        if (!user.active) {
            console.log(`❌ User ${userId} is inactive`);
            return null;
        }

        const sessionId = 'session_' + Math.random().toString(36).substr(2, 9);

        this.sessions.set(sessionId, {
            userId: userId,
            userRole: user.role,
            userName: user.name,
            loginTime: new Date()
            });

            console.log(`✅ User ${userId} logged in successfully`);
            console.log(`Session ID: ${sessionId}`);
            return sessionId;
    }

    hasPermission(sessionId, permission) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            console.log('❌ Invalid session');
            return false;
        }

        const userRole = session.userRole;
        const allowedPermissions = ROLE_PERMISSIONS[userRole] || [];

        const hasAccess = allowedPermissions.includes(permission);
        console.log(`Permission check for user ${session.userId} on ${permission}: ${hasAccess ? '✅ Granted' : '❌ Denied'}`);
        return hasAccess;
    }

        logout(sessionId) {
            const session = this.sessions.get(sessionId);
            if (session) {
                this.sessions.delete(sessionId);
                console.log(`✅ User ${session.userId} logged out successfully`);
                return true;
            }
            return false;
        };

        getSessionInfo(sessionId) {
            return this.sessions.get(sessionId) || null;
        };

}; 

console.log('Starting HIPAA Security Demo...');

const userManager = new UserManager();

userManager.createUser('doc1', 'Dr. Smith', USER_ROLES.DOCTOR, 'password123');
userManager.createUser('nurse1', 'Nurse Joy', USER_ROLES.NURSE, 'nursepass');
userManager.createUser('admin1', 'Admin Alice', USER_ROLES.ADMIN, 'adminpass');
userManager.createUser('patient1', 'Patient Bob', USER_ROLES.PATIENT, 'patientpass');

console.log('\n--- User Login ---');
const docSession = userManager.login('doc1', 'password123');
const nurseSession = userManager.login('nurse1', 'nursepass');
const adminSession = userManager.login('admin1', 'adminpass');
const patientSession = userManager.login('patient1', 'patientpass');

console.log('\n--- Permission Checks ---');
userManager.hasPermission(docSession, PERMISSIONS.VIEW_PATIENT_RECORDS);
userManager.hasPermission(nurseSession, PERMISSIONS.DELETE_PATIENT_RECORDS);
userManager.hasPermission(adminSession, PERMISSIONS.MANAGE_USERS);
userManager.hasPermission(patientSession, PERMISSIONS.WRITE_PATIENT_RECORDS);

console.log('\n--- User Logout ---');
userManager.logout(docSession);
userManager.logout(nurseSession);
userManager.logout(adminSession);
userManager.logout(patientSession);

console.log('HIPAA Security Demo Completed.');

class ActivityLogger {

    constructor() {
    
        this.auditlog = []; // this will store the activity records
        this.suspiciousActivities = []; // this will store the suspicious activity records
    }

    logActivity(sessionId, action, resource, outcome, additionalData = {}) {

        const session = userManager.getSessionInfo(sessionId);
        const timestamp = new Date();

        const logEntry = {
            id: this.generateLogId(),
            timestamp: timestamp.toISOString(),
            userId: session ? session.userId : 'Unknown',
            userRole: session ? session.userRole : 'Unknown',
            action: action,
            resource: resource,
            outcome: outcome,
            ipAddress: this.getSimulatedIPAddress(),
            ...additionalData
        };

        this.auditlog.push(logEntry);

        console.log(`Activity Logged: ${action} on ${resource} by ${logEntry.userId} (${logEntry.userRole}) - Outcome: ${outcome}`);

        this.checkForSuspiciousActivity(logEntry);

        return logEntry.id;
    }

    generateLogId() {
        return 'log_' + Math.random().toString(36).substr(2, 9);
    }
    
    getSimulatedIPAddress() {
        return '192.168.1.' + Math.floor(Math.random() * 255);
    }

    checkForSuspiciousActivity(currentLogEntry) {
        this.checkFailedLoginAttempts(currentLogEntry);
        this.checkOffHoursAccess(currentLogEntry);
        this.checkUnusalAccess(currentLogEntry);
    }

    checkFailedLoginAttempts(currentLogEntry) {
        if (currentLogEntry.action === 'LOGIN' && currentLogEntry.outcome === 'FAILED') {
            const recentFailures = this.auditlog.filter(log => 
                log.userId === currentLogEntry.userId &&          // Same user trying
                log.action === 'LOGIN' &&                    // Only login attempts  
                log.outcome === 'FAILED' &&                  // Only failures
                Date.now() - new Date(log.timestamp).getTime() < 300000 // Within 5 minutes
            );

            if (recentFailures.length >= 3) {
                this.flagSuspiciousActivity('EXCESSIVE_FAILED_LOGINS', currentLogEntry, 'HIGH');
            }
        }
    }

    checkOffHoursAccess(currentLogEntry) {
        const hour = new Date(currentLogEntry.timestamp).getHours();
        if (hour < 6 || hour > 20) {
            this.flagSuspiciousActivity('OFF_HOURS_ACCESS', currentLogEntry, 'MEDIUM');
        }
    }

    checkUnusalAccess(currentLogEntry) {
        if(currentLogEntry.action === 'ACCESS_PATIENT_RECORD') {
            const today = new Date().toDateString();
            const todaysAccess = this.auditlog.filter(log =>
                log.userId === currentLogEntry.userId &&
                log.action === 'ACCESS_PATIENT_RECORD' &&
                new Date(log.timestamp).toDateString() === today
            );

            if (todaysAccess.length > 10) {
                this.flagSuspiciousActivity('EXCESSIVE_RECORD_ACCESS', currentLogEntry, 'MEDIUM');
            }
        }
    }

    flagSuspiciousActivity(type, logEntry, severity) {
        const alert = {
            id: 'ALERT_' + Date.now(),
            type: type,
            severity: severity,
            timestamp: new Date().toISOString(),
            userId: logEntry.userId,
            triggerLog: logEntry,
            resolved: false
        };

        this.suspicousActivities.push(alert);
        console.warn(`🚨 ALERT TRIGGERED! ${type} detected for user ${logEntry.userId} - Severity: ${severity}`);

        if (severity === 'HIGH') {
            console.warn(`🔒 Immediate action recommended for user ${logEntry.userId}`);
        }

    }

    getAuditLog(userId = null, startDate = null, endDate = null) {
        let filteredLogs = this.auditlog;

        if (userId) {
            filteredLogs = filteredLogs.filter(log => log.userId === userId);
        }

        if (startDate) {
            filteredLogs = filteredLogs.filter(log => new Date(log.timestamp) >= new Date(startDate));
        }

        if (endDate) {
            filteredLogs = filteredLogs.filter(log => new Date(log.timestamp) <= new Date(endDate));
        }

        return filteredLogs;
    }

    getSecurityAlerts(severity = null) {
        if(severity) {
            return this.suspicousActivities.filter(alert => alert.severity === severity);
        }
        return this.suspiciousActivities;
    }


};
