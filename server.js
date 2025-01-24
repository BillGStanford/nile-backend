const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: async function (req, file, cb) {
    let uploadPath = 'uploads/';
    
    // Create different folders based on file type
    if (file.fieldname === 'pdf') {
      uploadPath += 'pdfs/';
    } else {
      uploadPath += 'images/';
    }
    
    // Create directories if they don't exist
    try {
      await fs.mkdir(uploadPath, { recursive: true });
      cb(null, uploadPath);
    } catch (error) {
      cb(error, null);
    }
  },
  filename: function (req, file, cb) {
    // Create unique filename using timestamp
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'pdf') {
      if (file.mimetype === 'application/pdf') {
        cb(null, true);
      } else {
        cb(new Error('Only PDF files are allowed!'), false);
      }
    } else {
      if (file.mimetype.startsWith('image/')) {
        cb(null, true);
      } else {
        cb(new Error('Only image files are allowed!'), false);
      }
    }
  }
});

// Database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'DiskCart5@',
  database: process.env.DB_NAME || 'nile_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Serve static files
app.use('/uploads', express.static('uploads'));

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Sign up endpoint
app.post('/api/auth/signup', async (req, res) => {
  const { username, email, password, firstName, lastName, dateOfBirth, bio } = req.body;

  if (!username || !email || !password || !firstName || !lastName || !dateOfBirth) {
    return res.status(400).json({ 
      message: 'Missing required fields',
      received: { username, email, password, firstName, lastName, dateOfBirth }
    });
  }

  try {
    const connection = await pool.getConnection();

    try {
      const [existingUsers] = await connection.execute(
        'SELECT id FROM users WHERE username = ? OR email = ?',
        [username, email]
      );
      
      if (existingUsers.length > 0) {
        return res.status(400).json({ message: 'Username or email already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const [result] = await connection.execute(
        'INSERT INTO users (username, email, password, firstName, lastName, dateOfBirth, bio) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [username, email, hashedPassword, firstName, lastName, dateOfBirth, bio || null]
      );

      const token = jwt.sign(
        { 
          id: result.insertId, 
          username,
          email,
          firstName,
          lastName
        },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '24h' }
      );

      res.status(201).json({
        message: 'User created successfully',
        token,
        user: { 
          id: result.insertId,
          username,
          email,
          firstName,
          lastName
        }
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Signup error:', error);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: 'Username or email already exists' });
    }
    
    res.status(500).json({ 
      message: 'Error creating user',
      error: error.message
    });
  }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  const { login, password } = req.body;

  if (!login || !password) {
    return res.status(400).json({ message: 'Login and password are required' });
  }

  try {
    const connection = await pool.getConnection();

    try {
      const [users] = await connection.execute(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        [login, login]
      );

      if (users.length === 0) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      const user = users[0];
      const validPassword = await bcrypt.compare(password, user.password);

      if (!validPassword) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      const token = jwt.sign(
        {
          id: user.id,
          username: user.username,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName
        },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '24h' }
      );

      res.json({
        message: 'Login successful',
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName
        }
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Verify token endpoint
// In your Express backend
app.get('/api/auth/verify', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    try {
      // Fetch the latest user data from the database
      const [users] = await connection.execute(
        'SELECT id, username, email, firstName, lastName FROM users WHERE id = ?',
        [req.user.id]
      );

      if (users.length === 0) {
        return res.status(404).json({ message: 'User not found' });
      }

      const user = users[0];
      res.json({ user });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Verify error:', error);
    res.status(500).json({ message: 'Error verifying token' });
  }
});

// Book publishing endpoint
app.post('/api/books/publish', 
  authenticateToken,
  upload.fields([
    { name: 'thumbnail', maxCount: 1 },
    { name: 'pdf', maxCount: 1 },
    { name: 'image1', maxCount: 1 },
    { name: 'image2', maxCount: 1 },
    { name: 'image3', maxCount: 1 },
    { name: 'image4', maxCount: 1 }
  ]),
  async (req, res) => {
    try {
      const { title, description, genre } = req.body;
      const userId = req.user.id;

      // Validate required fields
      if (!title || !description || !genre || !req.files.thumbnail || !req.files.pdf) {
        return res.status(400).json({ message: 'Missing required fields' });
      }

      const connection = await pool.getConnection();

      try {
        // Insert book record
        const [result] = await connection.execute(
          `INSERT INTO books (
            user_id, title, description, genre, 
            thumbnail_url, pdf_url,
            image1_url, image2_url, image3_url, image4_url
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            userId,
            title,
            description,
            genre,
            req.files.thumbnail[0].path,
            req.files.pdf[0].path,
            req.files.image1?.[0]?.path || null,
            req.files.image2?.[0]?.path || null,
            req.files.image3?.[0]?.path || null,
            req.files.image4?.[0]?.path || null
          ]
        );

        res.status(201).json({
          message: 'Book published successfully',
          bookId: result.insertId
        });
      } finally {
        connection.release();
      }
    } catch (error) {
      console.error('Book publishing error:', error);
      res.status(500).json({ 
        message: 'Error publishing book',
        error: error.message 
      });
    }
});

// Get books endpoint
app.get('/api/books', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    
    try {
      const [books] = await connection.execute(
        `SELECT b.*, u.username as author_name 
         FROM books b 
         JOIN users u ON b.user_id = u.id 
         ORDER BY b.created_at DESC`
      );
      
      res.json(books);
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error fetching books:', error);
    res.status(500).json({ message: 'Error fetching books' });
  }
});

// Get single book endpoint
app.get('/api/books/:id', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    
    try {
      const [books] = await connection.execute(
        `SELECT b.*, u.username as author_name 
         FROM books b 
         JOIN users u ON b.user_id = u.id 
         WHERE b.id = ?`,
        [req.params.id]
      );
      
      if (books.length === 0) {
        return res.status(404).json({ message: 'Book not found' });
      }

      res.json(books[0]);
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error fetching book:', error);
    res.status(500).json({ message: 'Error fetching book details' });
  }
});

// Delete book endpoint
app.delete('/api/books/:id', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const bookId = req.params.id;
    const userId = req.user.id;

    try {
      // First check if the book exists and belongs to the user
      const [books] = await connection.execute(
        'SELECT * FROM books WHERE id = ? AND user_id = ?',
        [bookId, userId]
      );

      if (books.length === 0) {
        return res.status(404).json({ message: 'Book not found or unauthorized' });
      }

      const book = books[0];

      // Delete the files associated with the book
      const filesToDelete = [
        book.thumbnail_url,
        book.pdf_url,
        book.image1_url,
        book.image2_url,
        book.image3_url,
        book.image4_url
      ].filter(Boolean); // Remove null/undefined values

      // Delete files from the filesystem
      for (const file of filesToDelete) {
        try {
          await fs.unlink(file);
        } catch (error) {
          console.error(`Error deleting file ${file}:`, error);
          // Continue with deletion even if file removal fails
        }
      }

      // Delete the book record from the database
      await connection.execute(
        'DELETE FROM books WHERE id = ?',
        [bookId]
      );

      res.json({ message: 'Book deleted successfully' });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error deleting book:', error);
    res.status(500).json({ message: 'Error deleting book' });
  }
});

app.put('/api/users/update', authenticateToken, async (req, res) => {
  const { username, email, firstName, lastName } = req.body;
  const userId = req.user.id;

  try {
    const connection = await pool.getConnection();
    try {
      // Check for existing username/email
      const [existingUsers] = await connection.execute(
        'SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?',
        [username, email, userId]
      );

      if (existingUsers.length > 0) {
        return res.status(400).json({ message: 'Username or email already exists' });
      }

      // Update user information
      await connection.execute(
        'UPDATE users SET username = ?, email = ?, firstName = ?, lastName = ? WHERE id = ?',
        [username, email, firstName, lastName, userId]
      );

      // Generate new token with updated information
      const newToken = jwt.sign(
        {
          id: userId,
          username,
          email,
          firstName,
          lastName
        },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '24h' }
      );

      // Return updated user data and new token
      res.json({
        message: 'Profile updated successfully',
        user: {
          id: userId,
          username,
          email,
          firstName,
          lastName
        },
        token: newToken
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Update error:', error);
    res.status(500).json({ message: 'Error updating profile' });
  }
});

// Update password
app.put('/api/users/password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.id;

  try {
    const connection = await pool.getConnection();
    try {
      const [users] = await connection.execute(
        'SELECT password FROM users WHERE id = ?',
        [userId]
      );

      const validPassword = await bcrypt.compare(currentPassword, users[0].password);
      if (!validPassword) {
        return res.status(401).json({ message: 'Current password is incorrect' });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await connection.execute(
        'UPDATE users SET password = ? WHERE id = ?',
        [hashedPassword, userId]
      );

      res.json({ message: 'Password updated successfully' });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Password update error:', error);
    res.status(500).json({ message: 'Error updating password' });
  }
});



// Get comments for a book
app.get('/api/books/:bookId/comments', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    try {
      const [comments] = await connection.execute(
        `SELECT 
          c.*,
          u.username,
          u.id as user_id,
          b.user_id as author_id,
          (SELECT COUNT(*) FROM comment_reactions WHERE comment_id = c.id AND reaction_type = 'like') as likes,
          (SELECT COUNT(*) FROM comment_reactions WHERE comment_id = c.id AND reaction_type = 'dislike') as dislikes
         FROM comments c
         JOIN users u ON c.user_id = u.id
         JOIN books b ON c.book_id = b.id
         WHERE c.book_id = ?
         ORDER BY c.parent_id IS NULL DESC, c.created_at ASC`,
        [req.params.bookId]
      );
      
      res.json(comments);
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error fetching comments:', error);
    res.status(500).json({ message: 'Error fetching comments' });
  }
});

// Add a comment
app.post('/api/books/:bookId/comments', authenticateToken, async (req, res) => {
  try {
    const { content, parentId } = req.body;
    const bookId = req.params.bookId;
    const userId = req.user.id;

    const connection = await pool.getConnection();
    try {
      const [result] = await connection.execute(
        'INSERT INTO comments (book_id, user_id, parent_id, content) VALUES (?, ?, ?, ?)',
        [bookId, userId, parentId || null, content]
      );

      const [newComment] = await connection.execute(
        `SELECT 
          c.*,
          u.username,
          u.id as user_id,
          b.user_id as author_id
         FROM comments c
         JOIN users u ON c.user_id = u.id
         JOIN books b ON c.book_id = b.id
         WHERE c.id = ?`,
        [result.insertId]
      );

      res.status(201).json(newComment[0]);
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error adding comment:', error);
    res.status(500).json({ message: 'Error adding comment' });
  }
});

// React to a comment (like/dislike)
app.post('/api/comments/:commentId/react', authenticateToken, async (req, res) => {
  try {
    const { reaction } = req.body; // 'like' or 'dislike'
    const commentId = req.params.commentId;
    const userId = req.user.id;

    const connection = await pool.getConnection();
    try {
      // Check if user already reacted
      const [existingReaction] = await connection.execute(
        'SELECT * FROM comment_reactions WHERE comment_id = ? AND user_id = ?',
        [commentId, userId]
      );

      if (existingReaction.length > 0) {
        if (existingReaction[0].reaction_type === reaction) {
          // Remove reaction if same type
          await connection.execute(
            'DELETE FROM comment_reactions WHERE comment_id = ? AND user_id = ?',
            [commentId, userId]
          );
        } else {
          // Update reaction if different type
          await connection.execute(
            'UPDATE comment_reactions SET reaction_type = ? WHERE comment_id = ? AND user_id = ?',
            [reaction, commentId, userId]
          );
        }
      } else {
        // Add new reaction
        await connection.execute(
          'INSERT INTO comment_reactions (comment_id, user_id, reaction_type) VALUES (?, ?, ?)',
          [commentId, userId, reaction]
        );
      }

      // Get updated counts
      const [updatedCounts] = await connection.execute(
        `SELECT 
          (SELECT COUNT(*) FROM comment_reactions WHERE comment_id = ? AND reaction_type = 'like') as likes,
          (SELECT COUNT(*) FROM comment_reactions WHERE comment_id = ? AND reaction_type = 'dislike') as dislikes`,
        [commentId, commentId]
      );

      res.json(updatedCounts[0]);
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error reacting to comment:', error);
    res.status(500).json({ message: 'Error reacting to comment' });
  }
});

// Pin/Unpin comment
app.post('/api/comments/:commentId/pin', authenticateToken, async (req, res) => {
  try {
    const commentId = req.params.commentId;
    const userId = req.user.id;

    const connection = await pool.getConnection();
    try {
      // Check if user is the book author
      const [book] = await connection.execute(
        `SELECT b.* FROM books b
         JOIN comments c ON c.book_id = b.id
         WHERE c.id = ? AND b.user_id = ?`,
        [commentId, userId]
      );

      if (book.length === 0) {
        return res.status(403).json({ message: 'Only the book author can pin comments' });
      }

      // Toggle pin status
      await connection.execute(
        'UPDATE comments SET is_pinned = NOT is_pinned WHERE id = ?',
        [commentId]
      );

      const [updatedComment] = await connection.execute(
        'SELECT is_pinned FROM comments WHERE id = ?',
        [commentId]
      );

      res.json({ is_pinned: updatedComment[0].is_pinned });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error pinning comment:', error);
    res.status(500).json({ message: 'Error pinning comment' });
  }
});

// Delete comment
app.delete('/api/comments/:commentId', authenticateToken, async (req, res) => {
  try {
    const commentId = req.params.commentId;
    const userId = req.user.id;

    const connection = await pool.getConnection();
    try {
      // Check if user is either comment author or book author
      const [authorized] = await connection.execute(
        `SELECT CASE 
           WHEN c.user_id = ? THEN TRUE
           WHEN b.user_id = ? THEN TRUE
           ELSE FALSE
         END as can_delete
         FROM comments c
         JOIN books b ON c.book_id = b.id
         WHERE c.id = ?`,
        [userId, userId, commentId]
      );

      if (!authorized[0]?.can_delete) {
        return res.status(403).json({ message: 'Not authorized to delete this comment' });
      }

      await connection.execute('DELETE FROM comments WHERE id = ?', [commentId]);
      res.json({ message: 'Comment deleted successfully' });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error deleting comment:', error);
    res.status(500).json({ message: 'Error deleting comment' });
  }
});

// Get user's comments
app.get('/api/users/comments', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const connection = await pool.getConnection();
    
    try {
      const [comments] = await connection.execute(
        `SELECT 
          c.*,
          b.title as book_title,
          b.user_id as book_author_id,
          u.username as book_author_name,
          (SELECT COUNT(*) FROM comment_reactions WHERE comment_id = c.id AND reaction_type = 'like') as likes,
          (SELECT COUNT(*) FROM comment_reactions WHERE comment_id = c.id AND reaction_type = 'dislike') as dislikes
         FROM comments c
         JOIN books b ON c.book_id = b.id
         JOIN users u ON b.user_id = u.id
         WHERE c.user_id = ?
         ORDER BY c.created_at DESC`,
        [userId]
      );
      
      res.json(comments);
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error fetching user comments:', error);
    res.status(500).json({ message: 'Error fetching user comments' });
  }
});

// Get user's reactions
app.get('/api/users/reactions', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const connection = await pool.getConnection();
    
    try {
      const [reactions] = await connection.execute(
        `SELECT 
          cr.*,
          c.content as comment_content,
          c.user_id as comment_author_id,
          u.username as comment_author_name,
          b.title as book_title,
          b.id as book_id
         FROM comment_reactions cr
         JOIN comments c ON cr.comment_id = c.id
         JOIN users u ON c.user_id = u.id
         JOIN books b ON c.book_id = b.id
         WHERE cr.user_id = ?
         ORDER BY cr.created_at DESC`,
        [userId]
      );
      
      res.json(reactions);
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error fetching user reactions:', error);
    res.status(500).json({ message: 'Error fetching user reactions' });
  }
});

// Add book to shelf
app.post('/api/bookshelf/add', authenticateToken, async (req, res) => {
  try {
    const { bookId } = req.body;
    const userId = req.user.id;
    
    const connection = await pool.getConnection();
    try {
      await connection.execute(
        'INSERT INTO bookshelves (user_id, book_id) VALUES (?, ?)',
        [userId, bookId]
      );
      
      res.status(201).json({ message: 'Book added to shelf successfully' });
    } finally {
      connection.release();
    }
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: 'Book is already in your shelf' });
    }
    console.error('Error adding book to shelf:', error);
    res.status(500).json({ message: 'Error adding book to shelf' });
  }
});

// Remove book from shelf
app.delete('/api/bookshelf/remove/:bookId', authenticateToken, async (req, res) => {
  try {
    const bookId = req.params.bookId;
    const userId = req.user.id;
    
    const connection = await pool.getConnection();
    try {
      await connection.execute(
        'DELETE FROM bookshelves WHERE user_id = ? AND book_id = ?',
        [userId, bookId]
      );
      
      res.json({ message: 'Book removed from shelf successfully' });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error removing book from shelf:', error);
    res.status(500).json({ message: 'Error removing book from shelf' });
  }
});

// Get user's bookshelf
app.get('/api/bookshelf', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const connection = await pool.getConnection();
    
    try {
      const [books] = await connection.execute(
        `SELECT b.*, u.username as author_name, bs.added_at 
         FROM bookshelves bs
         JOIN books b ON bs.book_id = b.id
         JOIN users u ON b.user_id = u.id
         WHERE bs.user_id = ?
         ORDER BY bs.added_at DESC`,
        [userId]
      );
      
      res.json(books);
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error fetching bookshelf:', error);
    res.status(500).json({ message: 'Error fetching bookshelf' });
  }
});

// Check if a book is in user's shelf
app.get('/api/bookshelf/check/:bookId', authenticateToken, async (req, res) => {
  try {
    const bookId = req.params.bookId;
    const userId = req.user.id;
    
    const connection = await pool.getConnection();
    try {
      const [result] = await connection.execute(
        'SELECT 1 FROM bookshelves WHERE user_id = ? AND book_id = ?',
        [userId, bookId]
      );
      
      res.json({ isInShelf: result.length > 0 });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error checking bookshelf:', error);
    res.status(500).json({ message: 'Error checking bookshelf' });
  }
});

// Add endpoint to track reading progress
app.post('/api/reading-progress', authenticateToken, async (req, res) => {
  try {
    const { bookId } = req.body;
    const userId = req.user.id;
    
    const connection = await pool.getConnection();
    try {
      // Insert or update reading progress
      await connection.execute(
        `INSERT INTO reading_progress (user_id, book_id, last_accessed) 
         VALUES (?, ?, NOW()) 
         ON DUPLICATE KEY UPDATE last_accessed = NOW()`,
        [userId, bookId]
      );
      
      res.status(201).json({ message: 'Reading progress updated' });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error updating reading progress:', error);
    res.status(500).json({ message: 'Error updating reading progress' });
  }
});

// Get user's reading progress
app.get('/api/reading-progress', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const connection = await pool.getConnection();
    
    try {
      const [books] = await connection.execute(
        `SELECT b.*, u.username as author_name, rp.last_accessed 
         FROM reading_progress rp
         JOIN books b ON rp.book_id = b.id
         JOIN users u ON b.user_id = u.id
         WHERE rp.user_id = ?
         ORDER BY rp.last_accessed DESC`,
        [userId]
      );
      
      res.json(books);
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error fetching reading progress:', error);
    res.status(500).json({ message: 'Error fetching reading progress' });
  }
});

// Remove reading progress for a specific book
app.delete('/api/reading-progress/:bookId', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const bookId = req.params.bookId;
    const connection = await pool.getConnection();
    
    try {
      await connection.execute(
        'DELETE FROM reading_progress WHERE user_id = ? AND book_id = ?',
        [userId, bookId]
      );
      
      res.status(200).json({ message: 'Reading progress removed' });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error removing reading progress:', error);
    res.status(500).json({ message: 'Error removing reading progress' });
  }
});



// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});