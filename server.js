const express = require('express');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'asasul-ilm-academy-super-secret-2026';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'jibrinalyaks@gmail.com';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve static files - Must come before routes
app.use(express.static(path.join(__dirname, 'public')));

// Auth Middleware
function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token provided' });
  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function authorize(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  };
}

// ==================== AUTH ROUTES ====================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    let user;
    // If the "email" field looks like a registration number (e.g. ASSI/...), treat it as such
    if (typeof email === 'string' && email.startsWith('ASSI/')) {
      const student = await prisma.student.findUnique({ where: { rollNo: email } });
      if (!student) return res.status(401).json({ error: 'Invalid registration number' });
      user = await prisma.user.findUnique({ where: { id: student.userId } });
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    } else {
      // Normal email login (admin/teacher)
      user = await prisma.user.findUnique({ where: { email } });
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    let profile = null;
    if (user.role === 'STUDENT') {
      profile = await prisma.student.findUnique({ where: { userId: user.id } });
    } else if (user.role === 'TEACHER') {
      profile = await prisma.teacher.findUnique({ where: { userId: user.id } });
    }

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        profile
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.put('/api/auth/change-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });

    const valid = await bcrypt.compare(currentPassword, user.password);
    if (!valid) return res.status(400).json({ error: 'Current password is incorrect' });

    const hashed = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { id: req.user.id },
      data: { password: hashed }
    });

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update password' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: 'User not found' });

    let defaultPassword;
    switch (user.role) {
      case 'ADMIN': defaultPassword = 'admin@access010'; break;
      case 'TEACHER': defaultPassword = 'teacher123'; break;
      default: defaultPassword = 'password';
    }

    const hashed = await bcrypt.hash(defaultPassword, 10);
    await prisma.user.update({
      where: { id: user.id },
      data: { password: hashed }
    });

    console.log(`📧 Password reset for ${email}. New password: ${defaultPassword}`);
    res.json({ message: 'Password reset successfully. Check with administrator.' });
  } catch (error) {
    res.status(500).json({ error: 'Password reset failed' });
  }
});

// ==================== STUDENT ROUTES ====================
app.get('/api/students', authenticate, async (req, res) => {
  try {
    let where = {};
    if (req.user.role === 'STUDENT') {
      where = { userId: req.user.id };
    } else if (req.user.role === 'TEACHER') {
      const teacher = await prisma.teacher.findUnique({ where: { userId: req.user.id } });
      if (teacher?.classAssigned) where = { class: teacher.classAssigned };
    }

    const students = await prisma.student.findMany({
      where,
      include: { user: { select: { id: true, name: true, email: true } } },
      orderBy: { class: 'asc' }
    });
    res.json(students);
  } catch (error) {
    console.error('Get students error:', error);
    res.status(500).json({ error: 'Failed to fetch students' });
  }
});

app.post('/api/students', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const { name, email, class: className, parentEmail, parentPhone, address, dob } = req.body;

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ error: 'Email already exists' });

    const hashedPassword = await bcrypt.hash('password', 10);
    const user = await prisma.user.create({
      data: { email, password: hashedPassword, name, role: 'STUDENT' }
    });

    const year = new Date().getFullYear();
    const count = await prisma.student.count();
    const rollNo = `ASSI/${year}/${String(count + 1).padStart(3, '0')}`;

    const student = await prisma.student.create({
      data: {
        userId: user.id,
        rollNo,
        class: className,
        parentEmail,
        parentPhone,
        address,
        dob
      },
      include: { user: { select: { name: true, email: true } } }
    });

    res.status(201).json(student);
  } catch (error) {
    console.error('Create student error:', error);
    res.status(400).json({ error: 'Failed to create student' });
  }
});

app.put('/api/students/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const student = await prisma.student.findUnique({ where: { id } });
    if (!student) return res.status(404).json({ error: 'Student not found' });

    if (req.user.role === 'STUDENT' && student.userId !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const updated = await prisma.student.update({
      where: { id },
      data: req.body,
      include: { user: { select: { name: true, email: true } } }
    });

    res.json(updated);
  } catch (error) {
    console.error('Update student error:', error);
    res.status(400).json({ error: 'Failed to update student' });
  }
});

app.delete('/api/students/:id', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const student = await prisma.student.findUnique({ where: { id: req.params.id } });
    if (!student) return res.status(404).json({ error: 'Student not found' });

    await prisma.student.delete({ where: { id: req.params.id } });
    await prisma.user.delete({ where: { id: student.userId } });
    res.json({ message: 'Student deleted' });
  } catch (error) {
    console.error('Delete student error:', error);
    res.status(400).json({ error: 'Failed to delete student' });
  }
});

// ==================== TEACHER ROUTES ====================
app.get('/api/teachers', authenticate, authorize('ADMIN', 'TEACHER'), async (req, res) => {
  try {
    let where = {};
    if (req.user.role === 'TEACHER') {
      where = { userId: req.user.id };
    }

    const teachers = await prisma.teacher.findMany({
      where,
      include: { user: { select: { name: true, email: true } } }
    });
    res.json(teachers);
  } catch (error) {
    console.error('Get teachers error:', error);
    res.status(500).json({ error: 'Failed to fetch teachers' });
  }
});

app.post('/api/teachers', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const { name, email, subject, classAssigned } = req.body;

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ error: 'Email already exists' });

    const hashedPassword = await bcrypt.hash('teacher123', 10);
    const user = await prisma.user.create({
      data: { email, password: hashedPassword, name, role: 'TEACHER' }
    });

    const teacher = await prisma.teacher.create({
      data: { userId: user.id, subject, classAssigned },
      include: { user: { select: { name: true, email: true } } }
    });

    res.status(201).json(teacher);
  } catch (error) {
    console.error('Create teacher error:', error);
    res.status(400).json({ error: 'Failed to create teacher' });
  }
});

app.put('/api/teachers/:id', authenticate, authorize('ADMIN', 'TEACHER'), async (req, res) => {
  try {
    const updated = await prisma.teacher.update({
      where: { id: req.params.id },
      data: req.body,
      include: { user: { select: { name: true, email: true } } }
    });
    res.json(updated);
  } catch (error) {
    res.status(400).json({ error: 'Failed to update teacher' });
  }
});

app.delete('/api/teachers/:id', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const teacher = await prisma.teacher.findUnique({ where: { id: req.params.id } });
    if (!teacher) return res.status(404).json({ error: 'Teacher not found' });

    await prisma.teacher.delete({ where: { id: req.params.id } });
    await prisma.user.delete({ where: { id: teacher.userId } });
    res.json({ message: 'Teacher deleted' });
  } catch (error) {
    res.status(400).json({ error: 'Failed to delete teacher' });
  }
});

// ==================== CLASS ROUTES ====================
app.get('/api/classes', authenticate, async (req, res) => {
  try {
    const classes = await prisma.class.findMany({
      include: { teacher: { include: { user: { select: { name: true } } } } },
      orderBy: { name: 'asc' }
    });
    res.json(classes);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch classes' });
  }
});

app.post('/api/classes', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const { name } = req.body;
    const existing = await prisma.class.findUnique({ where: { name } });
    if (existing) return res.status(400).json({ error: 'Class already exists' });

    const newClass = await prisma.class.create({ data: { name } });
    res.status(201).json(newClass);
  } catch (error) {
    res.status(400).json({ error: 'Failed to create class' });
  }
});

app.delete('/api/classes/:id', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    await prisma.class.delete({ where: { id: req.params.id } });
    res.json({ message: 'Class deleted' });
  } catch (error) {
    res.status(400).json({ error: 'Failed to delete class' });
  }
});

// ==================== ATTENDANCE ROUTES ====================
app.post('/api/attendance', authenticate, authorize('ADMIN', 'TEACHER'), async (req, res) => {
  try {
    const { records } = req.body;
    if (!Array.isArray(records) || records.length === 0) {
      return res.status(400).json({ error: 'No attendance records provided' });
    }

    const created = await Promise.all(
      records.map(record =>
        prisma.attendance.create({
          data: {
            studentId: record.studentId,
            present: record.present,
            class: record.class,
            date: record.date ? new Date(record.date) : new Date()
          }
        })
      )
    );

    res.status(201).json(created);
  } catch (error) {
    console.error('Attendance error:', error);
    res.status(400).json({ error: 'Failed to save attendance' });
  }
});

app.get('/api/attendance', authenticate, async (req, res) => {
  try {
    const { class: className, date, studentId } = req.query;
    const where = {};
    if (className) where.class = className;
    if (date) where.date = new Date(date);
    if (studentId) where.studentId = studentId;

    const records = await prisma.attendance.findMany({
      where,
      include: { student: { include: { user: { select: { name: true } } } } },
      orderBy: { date: 'desc' }
    });

    res.json(records);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch attendance' });
  }
});

// ==================== GRADE ROUTES ====================
app.post('/api/grades', authenticate, authorize('ADMIN', 'TEACHER'), async (req, res) => {
  try {
    const { studentId, subject, ca1, ca2, exam, term, attendance } = req.body;

    const existing = await prisma.grade.findFirst({
      where: { studentId, subject, term }
    });

    let grade;
    if (existing) {
      grade = await prisma.grade.update({
        where: { id: existing.id },
        data: {
          ca1: parseFloat(ca1) || 0,
          ca2: parseFloat(ca2) || 0,
          exam: parseFloat(exam) || 0,
          attendance: parseInt(attendance) || 100
        }
      });
    } else {
      grade = await prisma.grade.create({
        data: {
          studentId,
          subject,
          ca1: parseFloat(ca1) || 0,
          ca2: parseFloat(ca2) || 0,
          exam: parseFloat(exam) || 0,
          term,
          attendance: parseInt(attendance) || 100
        }
      });
    }

    res.json(grade);
  } catch (error) {
    console.error('Grade error:', error);
    res.status(400).json({ error: 'Failed to save grade' });
  }
});

app.get('/api/grades', authenticate, async (req, res) => {
  try {
    const { studentId, term } = req.query;
    const where = {};
    if (studentId) where.studentId = studentId;
    if (term) where.term = term;

    const grades = await prisma.grade.findMany({
      where,
      include: { student: { include: { user: { select: { name: true } } } } }
    });

    res.json(grades);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch grades' });
  }
});

app.delete('/api/grades/:id', authenticate, authorize('ADMIN', 'TEACHER'), async (req, res) => {
  try {
    await prisma.grade.delete({ where: { id: req.params.id } });
    res.json({ message: 'Grade deleted' });
  } catch (error) {
    res.status(400).json({ error: 'Failed to delete grade' });
  }
});

// ==================== SUBJECT REGISTRATION ROUTES ====================
app.post('/api/subjects', authenticate, authorize('ADMIN', 'TEACHER'), async (req, res) => {
  try {
    const { studentId, subjects } = req.body;

    const existing = await prisma.subjectRegistration.findFirst({
      where: { studentId }
    });

    let registration;
    if (existing) {
      registration = await prisma.subjectRegistration.update({
        where: { id: existing.id },
        data: { subjects: JSON.stringify(subjects) }
      });
    } else {
      registration = await prisma.subjectRegistration.create({
        data: { studentId, subjects: JSON.stringify(subjects) }
      });
    }

    res.json({ ...registration, subjects: JSON.parse(registration.subjects) });
  } catch (error) {
    res.status(400).json({ error: 'Failed to save subjects' });
  }
});

app.get('/api/subjects', authenticate, async (req, res) => {
  try {
    const { studentId } = req.query;
    const where = studentId ? { studentId } : {};

    const registrations = await prisma.subjectRegistration.findMany({
      where,
      include: { student: { include: { user: { select: { name: true } } } } }
    });

    const parsed = registrations.map(r => ({
      ...r,
      subjects: JSON.parse(r.subjects || '[]')
    }));

    res.json(parsed);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch subjects' });
  }
});

// ==================== ADMISSION ROUTES ====================
app.post('/api/admissions', async (req, res) => {
  try {
    const { childName, classFor, parentName, phone, email, paymentRef } = req.body;

    const portalSetting = await prisma.setting.findUnique({ where: { key: 'portalOpen' } });
    if (portalSetting?.value === 'false') {
      return res.status(403).json({ error: 'Admission portal is currently closed' });
    }

    const existing = await prisma.admission.findFirst({
      where: { email, status: 'pending' }
    });
    if (existing) return res.status(400).json({ error: 'You already have a pending application' });

    const ref = 'ASSI-' + Date.now().toString(36).toUpperCase();

    const admission = await prisma.admission.create({
      data: {
        childName,
        classFor,
        parentName,
        phone,
        email,
        applicantEmail: email,
        paymentRef,
        ref
      }
    });

    res.status(201).json({ ref: admission.ref, admission });
  } catch (error) {
    console.error('Admission error:', error);
    res.status(400).json({ error: 'Failed to submit application' });
  }
});

// GET all admissions (admin) – include student details if accepted
app.get('/api/admissions', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const admissions = await prisma.admission.findMany({
      orderBy: { createdAt: 'desc' }
    });

    // For accepted admissions, fetch the associated student to show login details
    const enriched = await Promise.all(admissions.map(async (ad) => {
      if (ad.status === 'accepted') {
        const student = await prisma.student.findFirst({
          where: { user: { email: ad.email } },
          include: { user: { select: { name: true, email: true } } }
        });
        return {
          ...ad,
          student: student ? {
            id: student.id,
            rollNo: student.rollNo,
            name: student.user.name,
            email: student.user.email,
            class: student.class
          } : null
        };
      }
      return ad;
    }));

    res.json(enriched);
  } catch (error) {
    console.error('Get admissions error:', error);
    res.status(500).json({ error: 'Failed to fetch admissions' });
  }
});

// Public application status check
app.get('/api/admissions/check', async (req, res) => {
  try {
    const { email, ref } = req.query;
    const admission = await prisma.admission.findFirst({
      where: { email, ref }
    });
    if (!admission) return res.status(404).json({ error: 'Application not found' });

    // If accepted, try to fetch the student for login info
    let studentInfo = null;
    if (admission.status === 'accepted') {
      const student = await prisma.student.findFirst({
        where: { user: { email: admission.email } }
      });
      if (student) {
        studentInfo = {
          rollNo: student.rollNo,
          class: student.class
        };
      }
    }

    res.json({
      ...admission,
      student: studentInfo
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to check status' });
  }
});

// Update admission status (admin) – create student if accepted
app.put('/api/admissions/:id', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const { status } = req.body;
    const admission = await prisma.admission.update({
      where: { id: req.params.id },
      data: { status }
    });

    let studentDetails = null;

    if (status === 'accepted') {
      const existingUser = await prisma.user.findUnique({ where: { email: admission.email } });
      if (!existingUser) {
        const hashedPassword = await bcrypt.hash('password', 10);
        const user = await prisma.user.create({
          data: {
            email: admission.email,
            password: hashedPassword,
            name: admission.childName,
            role: 'STUDENT'
          }
        });

        const year = new Date().getFullYear();
        const count = await prisma.student.count();
        const rollNo = `ASSI/${year}/${String(count + 1).padStart(3, '0')}`;

        const newStudent = await prisma.student.create({
          data: {
            userId: user.id,
            rollNo,
            class: admission.classFor,
            parentEmail: admission.email,
            parentPhone: admission.phone,
            address: admission.address
          },
          include: { user: { select: { name: true, email: true } } }
        });

        studentDetails = {
          id: newStudent.id,
          rollNo: newStudent.rollNo,
          name: newStudent.user.name,
          email: newStudent.user.email,
          class: newStudent.class
        };
      } else {
        // User already exists, ensure student record exists
        const student = await prisma.student.findUnique({ where: { userId: existingUser.id } });
        if (student) {
          studentDetails = {
            id: student.id,
            rollNo: student.rollNo,
            name: existingUser.name,
            email: existingUser.email,
            class: student.class
          };
        }
      }
    }

    // Return admission with the created student details
    res.json({
      ...admission,
      student: studentDetails
    });
  } catch (error) {
    console.error('Admission update error:', error);
    res.status(400).json({ error: 'Failed to update admission' });
  }
});

app.delete('/api/admissions/:id', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    await prisma.admission.delete({ where: { id: req.params.id } });
    res.json({ message: 'Admission deleted' });
  } catch (error) {
    res.status(400).json({ error: 'Failed to delete admission' });
  }
});

// ==================== ANNOUNCEMENT ROUTES ====================
app.get('/api/announcements', authenticate, async (req, res) => {
  try {
    const announcements = await prisma.announcement.findMany({
      include: { author: { select: { name: true } } },
      orderBy: { createdAt: 'desc' }
    });
    res.json(announcements);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch announcements' });
  }
});

app.post('/api/announcements', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const { title, content, target } = req.body;
    const announcement = await prisma.announcement.create({
      data: { title, content, target: target || 'all', authorId: req.user.id },
      include: { author: { select: { name: true } } }
    });
    res.status(201).json(announcement);
  } catch (error) {
    res.status(400).json({ error: 'Failed to create announcement' });
  }
});

app.delete('/api/announcements/:id', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    await prisma.announcement.delete({ where: { id: req.params.id } });
    res.json({ message: 'Announcement deleted' });
  } catch (error) {
    res.status(400).json({ error: 'Failed to delete announcement' });
  }
});

// ==================== CALENDAR ROUTES ====================
app.get('/api/calendar', authenticate, async (req, res) => {
  try {
    const events = await prisma.calendarEvent.findMany({
      orderBy: { eventDate: 'asc' }
    });
    res.json(events);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch calendar' });
  }
});

app.post('/api/calendar', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const { title, description, eventDate, term, year } = req.body;
    const event = await prisma.calendarEvent.create({
      data: { title, description, eventDate: new Date(eventDate), term, year }
    });
    res.status(201).json(event);
  } catch (error) {
    res.status(400).json({ error: 'Failed to create event' });
  }
});

app.delete('/api/calendar/:id', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    await prisma.calendarEvent.delete({ where: { id: req.params.id } });
    res.json({ message: 'Event deleted' });
  } catch (error) {
    res.status(400).json({ error: 'Failed to delete event' });
  }
});

// ==================== MISSING STUDENT REPORT ROUTES ====================
app.post('/api/reports/missing', authenticate, authorize('TEACHER'), async (req, res) => {
  try {
    const { studentName, studentClass, teacherMessage } = req.body;
    const teacher = await prisma.teacher.findUnique({ where: { userId: req.user.id } });

    const report = await prisma.missingReport.create({
      data: {
        studentName,
        studentClass,
        teacherMessage,
        teacherId: teacher.id,
        status: 'pending'
      }
    });

    console.log(`📧 Missing student report: ${studentName} (${studentClass})`);
    res.status(201).json(report);
  } catch (error) {
    res.status(400).json({ error: 'Failed to submit report' });
  }
});

app.get('/api/reports/missing', authenticate, async (req, res) => {
  try {
    let where = {};
    if (req.user.role === 'TEACHER') {
      const teacher = await prisma.teacher.findUnique({ where: { userId: req.user.id } });
      where = { teacherId: teacher.id };
    }

    const reports = await prisma.missingReport.findMany({
      where,
      include: { teacher: { include: { user: { select: { name: true } } } } },
      orderBy: { createdAt: 'desc' }
    });
    res.json(reports);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

app.put('/api/reports/missing/:id', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const { status } = req.body;
    const report = await prisma.missingReport.update({
      where: { id: req.params.id },
      data: { status }
    });
    res.json(report);
  } catch (error) {
    res.status(400).json({ error: 'Failed to update report' });
  }
});

app.delete('/api/reports/missing/:id', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    await prisma.missingReport.delete({ where: { id: req.params.id } });
    res.json({ message: 'Report deleted' });
  } catch (error) {
    res.status(400).json({ error: 'Failed to delete report' });
  }
});

// ==================== RANKING / RESULTS ====================
app.get('/api/ranking', authenticate, async (req, res) => {
  try {
    const { class: className, term } = req.query;
    const where = {};
    if (className) where.class = className;
    else if (req.user.role === 'TEACHER') {
      const teacher = await prisma.teacher.findUnique({ where: { userId: req.user.id } });
      if (teacher?.classAssigned) where.class = teacher.classAssigned;
    }

    const students = await prisma.student.findMany({
      where,
      include: {
        user: { select: { name: true } },
        grades: { where: { term: term || 'Term 1' } }
      }
    });

    const ranked = students.map(student => {
      const total = student.grades.reduce((sum, g) =>
        sum + (g.ca1 || 0) + (g.ca2 || 0) + (g.exam || 0), 0
      );
      return {
        id: student.id,
        name: student.user.name,
        rollNo: student.rollNo,
        class: student.class,
        profilePic: student.profilePic,
        total,
        subjects: student.grades,
        average: student.grades.length > 0 ? (total / student.grades.length).toFixed(1) : 0
      };
    }).sort((a, b) => b.total - a.total);

    let position = 1;
    let prevTotal = null;
    ranked.forEach((student, index) => {
      if (index > 0 && student.total < prevTotal) position = index + 1;
      student.position = position;
      prevTotal = student.total;
    });

    res.json(ranked);
  } catch (error) {
    console.error('Ranking error:', error);
    res.status(500).json({ error: 'Failed to fetch ranking' });
  }
});

app.post('/api/results/release', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const { class: className, term } = req.body;
    const existing = await prisma.resultRelease.findFirst({
      where: { class: className, term }
    });

    let release;
    if (existing) {
      release = await prisma.resultRelease.update({
        where: { id: existing.id },
        data: { released: true }
      });
    } else {
      release = await prisma.resultRelease.create({
        data: { class: className, term, released: true }
      });
    }

    res.json(release);
  } catch (error) {
    res.status(400).json({ error: 'Failed to release results' });
  }
});

app.get('/api/results/check', authenticate, async (req, res) => {
  try {
    const { class: className, term } = req.query;
    const release = await prisma.resultRelease.findFirst({
      where: { class: className, term }
    });
    res.json({ released: release?.released || false });
  } catch (error) {
    res.status(500).json({ error: 'Failed to check results' });
  }
});

// ==================== SETTINGS ROUTES ====================
app.get('/api/settings/:key', async (req, res) => {
  try {
    const setting = await prisma.setting.findUnique({
      where: { key: req.params.key }
    });
    res.json({ value: setting?.value || null });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get setting' });
  }
});

app.put('/api/settings/:key', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const { value } = req.body;
    const setting = await prisma.setting.upsert({
      where: { key: req.params.key },
      update: { value },
      create: { key: req.params.key, value }
    });
    res.json(setting);
  } catch (error) {
    res.status(400).json({ error: 'Failed to update setting' });
  }
});

// ==================== DASHBOARD STATS ====================
app.get('/api/dashboard/stats', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const [students, teachers, classes, pendingAdmissions] = await Promise.all([
      prisma.student.count(),
      prisma.teacher.count(),
      prisma.class.count(),
      prisma.admission.count({ where: { status: 'pending' } })
    ]);

    res.json({ students, teachers, classes, pendingAdmissions });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ==================== TERM RESET ====================
app.post('/api/term/reset', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    await prisma.grade.deleteMany({});
    await prisma.attendance.deleteMany({});
    await prisma.subjectRegistration.deleteMany({});
    await prisma.resultRelease.deleteMany({});
    await prisma.admission.deleteMany({ where: { status: 'pending' } });

    await prisma.student.updateMany({
      data: { bioFilled: false }
    });

    res.json({ message: 'Term reset complete' });
  } catch (error) {
    console.error('Term reset error:', error);
    res.status(500).json({ error: 'Failed to reset term' });
  }
});

// ==================== BACKUP ROUTE (ADMIN ONLY) ====================
app.get('/api/admin/backup', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const dbPath = path.join(__dirname, 'prisma', 'dev.db');
    const date = new Date().toISOString().split('T')[0];
    const fileName = `assi-backup-${date}.db`;
    res.download(dbPath, fileName, (err) => {
      if (err) {
        console.error('Backup download error:', err);
        res.status(500).json({ error: 'Failed to download backup' });
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Backup route failed' });
  }
});

// ==================== AUTO-CREATE TABLES IN DATABASE ====================
async function ensureTablesExist() {
  const createTableStatements = [
    `CREATE TABLE IF NOT EXISTS "User" (
      "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      "email" TEXT NOT NULL UNIQUE,
      "password" TEXT NOT NULL,
      "name" TEXT NOT NULL,
      "role" TEXT NOT NULL DEFAULT 'STUDENT',
      "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
      "updatedAt" TIMESTAMP NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS "Student" (
      "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      "userId" TEXT NOT NULL UNIQUE REFERENCES "User"("id") ON DELETE CASCADE,
      "rollNo" TEXT NOT NULL UNIQUE,
      "class" TEXT NOT NULL,
      "parentEmail" TEXT,
      "parentPhone" TEXT,
      "address" TEXT,
      "profilePic" TEXT,
      "dob" TEXT,
      "bloodGroup" TEXT,
      "genotype" TEXT,
      "bioFilled" BOOLEAN NOT NULL DEFAULT false,
      "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
      "updatedAt" TIMESTAMP NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS "Teacher" (
      "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      "userId" TEXT NOT NULL UNIQUE REFERENCES "User"("id") ON DELETE CASCADE,
      "subject" TEXT NOT NULL,
      "classAssigned" TEXT,
      "profilePic" TEXT,
      "phone" TEXT,
      "address" TEXT,
      "bioFilled" BOOLEAN NOT NULL DEFAULT false,
      "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
      "updatedAt" TIMESTAMP NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS "Class" (
      "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      "name" TEXT NOT NULL UNIQUE,
      "teacherId" TEXT REFERENCES "Teacher"("id"),
      "createdAt" TIMESTAMP NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS "Attendance" (
      "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      "studentId" TEXT NOT NULL REFERENCES "Student"("id") ON DELETE CASCADE,
      "date" TIMESTAMP NOT NULL DEFAULT now(),
      "present" BOOLEAN NOT NULL,
      "class" TEXT NOT NULL,
      "createdAt" TIMESTAMP NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS "Grade" (
      "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      "studentId" TEXT NOT NULL REFERENCES "Student"("id") ON DELETE CASCADE,
      "subject" TEXT NOT NULL,
      "ca1" DOUBLE PRECISION DEFAULT 0,
      "ca2" DOUBLE PRECISION DEFAULT 0,
      "exam" DOUBLE PRECISION DEFAULT 0,
      "term" TEXT NOT NULL,
      "attendance" INTEGER DEFAULT 100,
      "createdAt" TIMESTAMP NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS "Announcement" (
      "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      "title" TEXT NOT NULL,
      "content" TEXT NOT NULL,
      "target" TEXT NOT NULL DEFAULT 'all',
      "authorId" TEXT NOT NULL REFERENCES "User"("id"),
      "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
      "updatedAt" TIMESTAMP NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS "Admission" (
      "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      "childName" TEXT NOT NULL,
      "dob" TEXT,
      "gender" TEXT,
      "classFor" TEXT NOT NULL,
      "parentName" TEXT NOT NULL,
      "phone" TEXT NOT NULL,
      "email" TEXT NOT NULL,
      "address" TEXT,
      "visitDate" TEXT,
      "notes" TEXT,
      "status" TEXT NOT NULL DEFAULT 'pending',
      "paymentRef" TEXT,
      "paymentStatus" TEXT DEFAULT 'pending',
      "ref" TEXT NOT NULL UNIQUE,
      "applicantEmail" TEXT NOT NULL,
      "createdAt" TIMESTAMP NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS "CalendarEvent" (
      "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      "title" TEXT NOT NULL,
      "description" TEXT,
      "eventDate" TIMESTAMP NOT NULL,
      "term" TEXT NOT NULL,
      "year" TEXT NOT NULL,
      "createdAt" TIMESTAMP NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS "SubjectRegistration" (
      "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      "studentId" TEXT NOT NULL REFERENCES "Student"("id") ON DELETE CASCADE,
      "subjects" TEXT NOT NULL DEFAULT '[]',
      "createdAt" TIMESTAMP NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS "ResultRelease" (
      "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      "class" TEXT NOT NULL,
      "term" TEXT NOT NULL,
      "released" BOOLEAN NOT NULL DEFAULT true,
      "createdAt" TIMESTAMP NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS "MissingReport" (
      "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      "studentName" TEXT NOT NULL,
      "studentClass" TEXT NOT NULL,
      "teacherMessage" TEXT,
      "teacherId" TEXT NOT NULL REFERENCES "Teacher"("id"),
      "status" TEXT NOT NULL DEFAULT 'pending',
      "createdAt" TIMESTAMP NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS "Setting" (
      "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      "key" TEXT NOT NULL UNIQUE,
      "value" TEXT NOT NULL
    )`
  ];

  try {
    for (const sql of createTableStatements) {
      await prisma.$executeRawUnsafe(sql);
    }
    console.log('✅ All tables checked/created successfully.');
  } catch (error) {
    console.error('❌ Error during table creation:', error);
    // Do not crash the server; maybe the tables already exist.
  }
}

// ==================== SEED DEFAULT DATA ====================
async function seedData() {
  try {
    // Create default admin
    const adminExists = await prisma.user.findUnique({
      where: { email: 'admin@assi.edu.ng' }
    });

    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin@access010', 10);
      await prisma.user.create({
        data: {
          email: 'admin@assi.edu.ng',
          password: hashedPassword,
          name: 'Super Admin',
          role: 'ADMIN'
        }
      });
      console.log('✅ Default admin created');
    }

    // Create demo teacher
    const teacherExists = await prisma.user.findUnique({
      where: { email: 'teacher@assi.edu.ng' }
    });

    if (!teacherExists) {
      const hashedPassword = await bcrypt.hash('teacher123', 10);
      const teacherUser = await prisma.user.create({
        data: {
          email: 'teacher@assi.edu.ng',
          password: hashedPassword,
          name: 'Mrs. Adeyemi',
          role: 'TEACHER'
        }
      });

      await prisma.teacher.create({
        data: {
          userId: teacherUser.id,
          subject: 'Mathematics',
          classAssigned: 'Primary 3'
        }
      });
      console.log('✅ Demo teacher created: teacher@assi.edu.ng / teacher123');
    }

    // Create demo student
    const studentExists = await prisma.user.findUnique({
      where: { email: 'student@assi.edu.ng' }
    });

    if (!studentExists) {
      const hashedPassword = await bcrypt.hash('password', 10);
      const studentUser = await prisma.user.create({
        data: {
          email: 'student@assi.edu.ng',
          password: hashedPassword,
          name: 'Amara Okonkwo',
          role: 'STUDENT'
        }
      });

      await prisma.student.create({
        data: {
          userId: studentUser.id,
          rollNo: 'ASSI/2026/001',
          class: 'Primary 3',
          parentPhone: '08012345678'
        }
      });
      console.log('✅ Demo student created: ASSI/2026/001 / password');
    }

    // Create default classes if none exist
    const classCount = await prisma.class.count();
    if (classCount === 0) {
      const classes = [
        'Nursery 1', 'Nursery 2', 'Nursery 3',
        'Primary 1', 'Primary 2', 'Primary 3',
        'Primary 4', 'Primary 5', 'Primary 6'
      ];
      for (const name of classes) {
        await prisma.class.create({ data: { name } });
      }
      console.log('✅ Default classes created');
    }

    const settings = [
      { key: 'portalOpen', value: 'true' },
      { key: 'frontPagePhotos', value: '[]' },
      { key: 'adminProfilePic', value: '' }
    ];

    for (const setting of settings) {
      await prisma.setting.upsert({
        where: { key: setting.key },
        update: {},
        create: setting
      });
    }
    console.log('✅ Default settings created');
  } catch (error) {
    console.error('Seed error:', error);
  }
}

// ==================== SERVE FRONTEND ====================
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== START SERVER ====================
async function start() {
  try {
    await prisma.$connect();
    console.log('✅ Database connected');
    await ensureTablesExist();  // <-- creates tables if they don't exist
    await seedData();

    app.listen(PORT, () => {
      console.log(`🚀 ASASUL ILM ACADEMY GOMBE - Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

start();

process.on('SIGTERM', async () => {
  console.log('Shutting down...');
  await prisma.$disconnect();
  process.exit(0);
});
