require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'https://dashing-cranachan-f117c5.netlify.app/',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
  },
});

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://127.0.0.1:5500',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));
app.use(express.json());

// Serve static files for profile pictures
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests
});
app.use(limiter);

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'Uploads');
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (['.jpg', '.jpeg', '.png'].includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only images are allowed'), false);
    }
  },
  limits: { fileSize: 10 * 1024 * 1024 }, // 5MB limit
});

// MongoDB connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/whatsapp_clone';
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Schemas
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatar: { type: String, default: '' },
  status: { type: String, default: 'Hey there! I am using WhatsApp Clone.' },
  lastSeen: { type: Date, default: Date.now },
});

const MessageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  read: { type: Boolean, default: false },
  delivered: { type: Boolean, default: false },
  edited: { type: Boolean, default: false },
  reactions: [{ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, emoji: String }],
  conversation: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation' },
});

const ConversationSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  updatedAt: { type: Date, default: Date.now },
});

// Indexes
UserSchema.index({ email: 1 });
MessageSchema.index({ sender: 1, recipient: 1, timestamp: -1 });
ConversationSchema.index({ participants: 1, updatedAt: -1 });

// Models
const User = mongoose.model('User', UserSchema);
const Message = mongoose.model('Message', MessageSchema);
const Conversation = mongoose.model('Conversation', ConversationSchema);

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  console.log('Auth token:', token ? 'Present' : 'Missing');
  if (!token) return res.status(401).json({ message: 'Access token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log('JWT verification error:', err.message);
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters' });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({
      token,
      user: { id: user._id, name, email, avatar: user.avatar, status: user.status },
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
    user.lastSeen = Date.now();
    await user.save();
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({
      token,
      user: { id: user._id, name: user.name, email, avatar: user.avatar, status: user.status },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    console.error('Users error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Profile Update Endpoint
app.put('/api/users/profile', authenticateToken, upload.single('profilePic'), async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ message: 'Name is required' });

    const updateData = { name };
    if (req.file) {
      updateData.avatar = `/uploads/${req.file.filename}`;
    }

    const user = await User.findByIdAndUpdate(
      req.user.id,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');

    if (!user) return res.status(404).json({ message: 'User not found' });

    // Notify connected clients of profile update
    io.emit('profile_updated', {
      userId: user._id,
      name: user.name,
      avatar: user.avatar,
    });

    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        status: user.status,
      },
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/conversations/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    console.log(`Fetching conversations for user ${userId}`);
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: 'Invalid user ID' });
    }
    const conversations = await Conversation.find({ participants: userId })
      .populate('participants', '-password')
      .populate('lastMessage')
      .sort({ updatedAt: -1 });
    console.log('Conversations found:', conversations.length);
    res.json(conversations);
  } catch (error) {
    console.error('Error fetching conversations:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/messages/:conversationId', authenticateToken, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { page = 1, limit = 20 } = req.query;
    const conversation = await Conversation.findById(conversationId);
    if (!conversation) return res.status(404).json({ message: 'Conversation not found' });
    const messages = await Message.find({ conversation: conversationId })
      .sort({ timestamp: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit));
    res.json(messages);
  } catch (error) {
    console.error('Messages error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/messages/:messageId', authenticateToken, async (req, res) => {
  try {
    const { content } = req.body;
    const message = await Message.findById(req.params.messageId);
    if (!message) return res.status(404).json({ message: 'Message not found' });
    if (message.sender.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Unauthorized to edit this message' });
    }
    if (Date.now() - new Date(message.timestamp).getTime() > 5 * 60 * 1000) {
      return res.status(403).json({ message: 'Edit time limit exceeded' });
    }
    message.content = content;
    message.edited = true;
    await message.save();
    io.to(message.conversation.toString()).emit('message_edited', {
      messageId: message._id,
      content,
      conversationId: message.conversation,
    });
    res.json({ message: 'Message edited' });
  } catch (error) {
    console.error('Edit message error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/messages/:messageId/react', authenticateToken, async (req, res) => {
  try {
    const { emoji, userId } = req.body;
    const message = await Message.findById(req.params.messageId);
    if (!message) return res.status(404).json({ message: 'Message not found' });
    const existingReaction = message.reactions.find(r => r.userId.toString() === userId && r.emoji === emoji);
    if (existingReaction) {
      message.reactions = message.reactions.filter(r => r.userId.toString() !== userId || r.emoji !== emoji);
    } else {
      message.reactions.push({ userId, emoji });
    }
    await message.save();
    io.to(message.conversation.toString()).emit('message_reacted', {
      messageId: message._id,
      reactions: message.reactions,
      conversationId: message.conversation,
    });
    res.json({ message: 'Reaction updated' });
  } catch (error) {
    console.error('React message error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/messages/:messageId', authenticateToken, async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId);
    if (!message) return res.status(404).json({ message: 'Message not found' });
    if (message.sender.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Unauthorized to delete this message' });
    }
    const conversationId = message.conversation;
    await message.deleteOne();
    io.to(conversationId.toString()).emit('message_deleted', { messageId: req.params.messageId, conversationId });
    res.json({ message: 'Message deleted' });
  } catch (error) {
    console.error('Delete message error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Socket.IO
const onlineUsers = new Set();
const userSockets = new Map();
io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id);

  socket.on('user_online', async (userId) => {
    console.log(`User ${userId} online`);
    if (!onlineUsers.has(userId)) {
      onlineUsers.add(userId);
      userSockets.set(userId, socket.id);
      await User.findByIdAndUpdate(userId, { lastSeen: Date.now() });
      io.emit('user_status', { userId, status: 'online', lastSeen: new Date() });
      socket.join(userId);
      // Send online users to the newly connected client
      socket.emit('online_users', Array.from(onlineUsers));
    }
  });

  socket.on('get_online_users', () => {
    console.log('Sending online users:', Array.from(onlineUsers));
    socket.emit('online_users', Array.from(onlineUsers));
  });

  socket.on('send_message', async ({ sender, recipient, content, tempId }) => {
    try {
      console.log('Received send_message:', { sender, recipient, content, tempId });
      const newMessage = new Message({ sender, recipient, content, delivered: false, read: false });
      await newMessage.save();
      let conversation = await Conversation.findOne({
        participants: { $all: [sender, recipient].sort() },
      });
      if (!conversation) {
        conversation = new Conversation({ participants: [sender, recipient], lastMessage: newMessage._id });
      } else {
        conversation.lastMessage = newMessage._id;
        conversation.updatedAt = Date.now();
      }
      await conversation.save();
      newMessage.conversation = conversation._id;
      await newMessage.save();
      socket.join(conversation._id.toString());
      const recipientSocketId = userSockets.get(recipient);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('receive_message', {
          message: newMessage,
          conversation: conversation._id,
          tempId,
        });
        newMessage.delivered = true;
        await newMessage.save();
        io.to(sender).emit('message_delivered', newMessage._id);
      }
      socket.emit('message_sent', newMessage, tempId);
      io.to(conversation._id.toString()).emit('new_conversation', conversation);
    } catch (error) {
      console.error('Error in send_message:', error);
      socket.emit('message_error', { error: 'Failed to send message' });
    }
  });

  socket.on('mark_as_read', async (messageId) => {
    try {
      console.log('Marking message as read:', messageId);
      const message = await Message.findById(messageId);
      if (message && !message.read) {
        message.read = true;
        message.delivered = true;
        await message.save();
        io.to(message.sender.toString()).emit('message_read', messageId);
        io.to(message.sender.toString()).emit('message_delivered', messageId);
      }
    } catch (error) {
      console.error('Error marking message as read:', error);
    }
  });

  socket.on('typing', ({ conversationId, userId }) => {
    console.log(`User ${userId} typing in conversation ${conversationId}`);
    socket.to(conversationId).emit('typing', { userId });
  });

  socket.on('stop_typing', ({ conversationId, userId }) => {
    console.log(`User ${userId} stopped typing in conversation ${conversationId}`);
    socket.to(conversationId).emit('stop_typing', { userId });
  });

  socket.on('disconnect', async () => {
    console.log('Socket disconnected:', socket.id);
    for (const [userId, socketId] of userSockets.entries()) {
      if (socketId === socket.id) {
        onlineUsers.delete(userId);
        userSockets.delete(userId);
        await User.findByIdAndUpdate(userId, { lastSeen: Date.now() });
        io.emit('user_status', { userId, status: 'offline', lastSeen: new Date() });
        break;
      }
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
