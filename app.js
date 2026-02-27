// 台灣房東系統 API - 完整版本
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;
const API_PREFIX = process.env.API_PREFIX || '/api';

// 環境變數
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key-change-in-production';
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://localhost/taiwan_landlord';

// 資料庫連接池
console.log('資料庫連接字串:', DATABASE_URL ? '已設置' : '未設置');
const poolConfig = {
  connectionString: DATABASE_URL,
  // Zeabur 的 PostgreSQL 可能不支持 SSL，所以禁用 SSL
  ssl: false,
  // 增加連接超時和重試
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30000,
  max: 20
};

// 如果是本地開發，可以啟用 SSL
if (process.env.NODE_ENV === 'production' && DATABASE_URL && DATABASE_URL.includes('amazonaws.com')) {
  poolConfig.ssl = { rejectUnauthorized: false };
}

const pool = new Pool(poolConfig);

// 中間件
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 簡單日誌
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// CORS 中間件
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', process.env.CORS_ORIGIN || '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// ==================== 健康檢查 ====================
app.get('/health', async (req, res) => {
  try {
    // 測試資料庫連接
    const dbResult = await pool.query('SELECT 1 as test');
    const dbConnected = dbResult.rows[0].test === 1;
    
    res.json({
      status: 'healthy',
      service: '台灣房東系統 API',
      version: '1.0.0',
      database: dbConnected ? 'connected' : 'disconnected',
      timestamp: new Date().toISOString(),
      endpoints: {
        health: '/health',
        api_docs: '/api-docs',
        auth_register: `${API_PREFIX}/auth/register`,
        auth_login: `${API_PREFIX}/auth/login`,
        test: `${API_PREFIX}/test`
      },
      environment: {
        database_url_set: !!DATABASE_URL,
        jwt_secret_set: !!JWT_SECRET,
        api_prefix: API_PREFIX
      }
    });
  } catch (error) {
    console.error('健康檢查錯誤:', error.message);
    res.json({
      status: 'unhealthy',
      service: '台灣房東系統 API',
      error: '資料庫連接失敗',
      error_details: error.message,
      timestamp: new Date().toISOString(),
      environment: {
        database_url_set: !!DATABASE_URL,
        jwt_secret_set: !!JWT_SECRET,
        api_prefix: API_PREFIX
      }
    });
  }
});

// ==================== 根路徑 ====================
app.get('/', (req, res) => {
  res.json({
    message: '台灣房東系統 API',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      api_docs: '/api-docs',
      auth_register: `${API_PREFIX}/auth/register`,
      auth_login: `${API_PREFIX}/auth/login`,
      test: `${API_PREFIX}/test`
    },
    documentation: '訪問 /api-docs 查看完整 API 文檔'
  });
});

// ==================== API 文檔 ====================
app.get('/api-docs', (req, res) => {
  res.json({
    name: '台灣房東-越南租客系統 API',
    version: '1.0.0',
    base_url: `${req.protocol}://${req.headers.host}${API_PREFIX}`,
    authentication: 'Bearer Token',
    database: 'PostgreSQL',
    endpoints: {
      auth: {
        register: 'POST /auth/register',
        login: 'POST /auth/login',
        me: 'GET /auth/me (需要 Token)'
      },
      users: {
        list: 'GET /users (需要 super_admin)',
        get: 'GET /users/:id'
      },
      properties: {
        create: 'POST /properties (需要 admin)',
        list: 'GET /properties',
        get: 'GET /properties/:id'
      }
    }
  });
});

// ==================== 認證中間件 ====================
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: '未授權',
        message: '需要 Token 認證'
      });
    }
    
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // 驗證用戶是否存在
    const userResult = await pool.query(
      'SELECT id, username, role, status FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: '認證失敗',
        message: '用戶不存在'
      });
    }
    
    req.user = {
      userId: decoded.userId,
      username: decoded.username,
      role: decoded.role
    };
    
    next();
  } catch (error) {
    console.error('認證錯誤:', error);
    res.status(401).json({
      success: false,
      error: '認證失敗',
      message: 'Token 無效或已過期'
    });
  }
};

// ==================== 角色授權中間件 ====================
const authorize = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: '未授權',
        message: '需要先認證'
      });
    }
    
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: '權限不足',
        message: `需要 ${allowedRoles.join(' 或 ')} 權限`
      });
    }
    
    next();
  };
};

// ==================== 用戶註冊 ====================
app.post(`${API_PREFIX}/auth/register`, async (req, res) => {
  try {
    const { username, password, role = 'viewer', full_name } = req.body;
    
    // 驗證輸入
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: '缺少參數',
        message: '請提供用戶名和密碼'
      });
    }
    
    // 檢查用戶名是否已存在
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: '用戶已存在',
        message: '用戶名已存在'
      });
    }
    
    // 哈希密碼
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // 創建用戶
    const result = await pool.query(
      `INSERT INTO users (username, password_hash, role, full_name, status)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, username, role, full_name, status, created_at`,
      [username, hashedPassword, role, full_name || username, 'active']
    );
    
    const user = result.rows[0];
    
    // 生成 JWT Token
    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      success: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          full_name: user.full_name,
          status: user.status,
          created_at: user.created_at
        },
        token
      },
      message: '註冊成功'
    });
    
  } catch (error) {
    console.error('註冊錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '註冊失敗'
    });
  }
});

// ==================== 用戶登入 ====================
app.post(`${API_PREFIX}/auth/login`, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: '缺少參數',
        message: '請提供用戶名和密碼'
      });
    }
    
    // 查找用戶
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: '認證失敗',
        message: '用戶名或密碼錯誤'
      });
    }
    
    const user = result.rows[0];
    
    // 驗證密碼
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        error: '認證失敗',
        message: '用戶名或密碼錯誤'
      });
    }
    
    // 生成 JWT Token
    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          full_name: user.full_name,
          status: user.status
        },
        token
      },
      message: '登入成功'
    });
    
  } catch (error) {
    console.error('登入錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '登入失敗'
    });
  }
});

// ==================== 獲取當前用戶信息 ====================
app.get(`${API_PREFIX}/auth/me`, authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, role, full_name, status, created_at
       FROM users WHERE id = $1`,
      [req.user.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: '用戶不存在',
        message: '用戶已被刪除'
      });
    }
    
    const user = result.rows[0];
    
    res.json({
      success: true,
      data: { user },
      message: '獲取用戶信息成功'
    });
    
  } catch (error) {
    console.error('獲取用戶信息錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '獲取用戶信息失敗'
    });
  }
});

// ==================== 創建物業 ====================
app.post(`${API_PREFIX}/properties`, authenticate, authorize('super_admin', 'admin'), async (req, res) => {
  try {
    const { name, address, owner_name, owner_phone } = req.body;
    
    if (!name) {
      return res.status(400).json({
        success: false,
        error: '缺少參數',
        message: '請提供物業名稱'
      });
    }
    
    const result = await pool.query(
      `INSERT INTO properties (name, address, owner_name, owner_phone)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [name, address, owner_name, owner_phone]
    );
    
    const property = result.rows[0];
    
    res.status(201).json({
      success: true,
      data: { property },
      message: '創建物業成功'
    });
    
  } catch (error) {
    console.error('創建物業錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '創建物業失敗'
    });
  }
});

// ==================== 獲取物業列表 ====================
app.get(`${API_PREFIX}/properties`, authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM properties ORDER BY created_at DESC'
    );
    
    res.json({
      success: true,
      data: {
        properties: result.rows,
        count: result.rows.length
      },
      message: '獲取物業列表成功'
    });
    
  } catch (error) {
    console.error('獲取物業列表錯誤:', error);
    res.status(500).json({
      success: false,
      error: '伺服器錯誤',
      message: '獲取物業列表失敗'
    });
  }
});

// ==================== 測試端點 ====================
app.get(`${API_PREFIX}/test`, async (req, res) => {
  try {
    // 嘗試連接資料庫
    let dbStatus = 'unknown';
    try {
      await pool.query('SELECT 1');
      dbStatus = 'connected';
    } catch (dbError) {
      dbStatus = `disconnected: ${dbError.message}`;
    }
    
    res.json({
      success: true,
      message: '🎉 API 測試成功！',
      data: {
        service: '台灣房東-越南租客系統',
        version: '1.0.0',
        status: 'active',
        time: new Date().toISOString(),
        database: dbStatus,
        environment: {
          database_url_set: !!DATABASE_URL,
          jwt_secret_set: !!JWT_SECRET,
          api_prefix: API_PREFIX,
          port: port
        }
      },
      endpoints: {
        health: '/health',
        api_docs: '/api-docs',
        auth_register: `${API_PREFIX}/auth/register`,
        auth_login: `${API_PREFIX}/auth/login`,
        properties_list: `${API_PREFIX}/properties (需要 Token)`
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: '測試失敗',
      message: error.message
    });
  }
});

// ==================== 404 處理 ====================
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Not Found',
    message: `找不到路徑: ${req.path}`
  });
});

// ==================== 錯誤處理 ====================
app.use((err, req, res, next) => {
  console.error('伺服器錯誤:', err);
  res.status(500).json({
    success: false,
    error: 'Internal Server Error',
    message: '伺服器內部錯誤'
  });
});

// ==================== 啟動伺服器 ====================
app.listen(port, () => {
  console.log(`🚀 台灣房東系統 API 啟動成功！`);
  console.log(`🌐 訪問: http://localhost:${port}`);
  console.log(`✅ 健康檢查: http://localhost:${port}/health`);
  console.log(`📚 API 文檔: http://localhost:${port}/api-docs`);
  console.log(`🔑 註冊端點: POST http://localhost:${port}${API_PREFIX}/auth/register`);
  console.log(`🔑 登入端點: POST http://localhost:${port}${API_PREFIX}/auth/login`);
  console.log(`\n📝 環境變數:`);
  console.log(`   JWT_SECRET: ${JWT_SECRET ? '已設置' : '未設置（使用默認值）'}`);
  console.log(`   DATABASE_URL: ${DATABASE_URL ? '已設置' : '未設置（使用默認值）'}`);
  console.log(`   PORT: ${port}`);
});