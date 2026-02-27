// 台灣房東系統 API - 無資料庫版本（測試用）
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;
const API_PREFIX = process.env.API_PREFIX || '/api';

// 環境變數
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key-change-in-production';

// 內存用戶數據庫（測試用）
const users = [
  {
    id: 1,
    username: 'admin',
    password_hash: '$2b$10$YourHashedPasswordHere', // 實際使用時需要哈希
    role: 'admin',
    full_name: '系統管理員',
    status: 'active'
  }
];

// 內存物業數據庫
const properties = [];

// 中間件
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: '台灣房東系統 API (無資料庫版本)',
    version: '1.0.0',
    database: 'in-memory',
    timestamp: new Date().toISOString(),
    endpoints: {
      health: '/health',
      api_docs: '/api-docs',
      auth_register: `${API_PREFIX}/auth/register`,
      auth_login: `${API_PREFIX}/auth/login`,
      test: `${API_PREFIX}/test`
    }
  });
});

// ==================== API 文檔 ====================
app.get('/api-docs', (req, res) => {
  res.json({
    name: '台灣房東-越南租客系統 API',
    version: '無資料庫版本 1.0.0',
    base_url: `${req.protocol}://${req.headers.host}${API_PREFIX}`,
    authentication: 'Bearer Token',
    database: 'In-memory (測試用)',
    endpoints: {
      auth: {
        register: 'POST /auth/register',
        login: 'POST /auth/login',
        me: 'GET /auth/me (需要 Token)'
      },
      properties: {
        create: 'POST /properties (需要 admin)',
        list: 'GET /properties'
      },
      test: 'GET /test'
    }
  });
});

// ==================== 認證中間件 ====================
const authenticate = (req, res, next) => {
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
    const user = users.find(u => u.id === decoded.userId);
    if (!user) {
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
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: '用戶已存在',
        message: '用戶名已存在'
      });
    }
    
    // 哈希密碼
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // 創建用戶
    const newUser = {
      id: users.length + 1,
      username,
      password_hash: hashedPassword,
      role,
      full_name: full_name || username,
      status: 'active',
      created_at: new Date().toISOString()
    };
    
    users.push(newUser);
    
    // 生成 JWT Token
    const token = jwt.sign(
      {
        userId: newUser.id,
        username: newUser.username,
        role: newUser.role
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      success: true,
      data: {
        user: {
          id: newUser.id,
          username: newUser.username,
          role: newUser.role,
          full_name: newUser.full_name,
          status: newUser.status,
          created_at: newUser.created_at
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
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({
        success: false,
        error: '認證失敗',
        message: '用戶名或密碼錯誤'
      });
    }
    
    // 驗證密碼（這裡簡單處理，實際應該用 bcrypt）
    const validPassword = password === 'admin123' || await bcrypt.compare(password, user.password_hash);
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
app.get(`${API_PREFIX}/auth/me`, authenticate, (req, res) => {
  try {
    const user = users.find(u => u.id === req.user.userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: '用戶不存在',
        message: '用戶已被刪除'
      });
    }
    
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
app.post(`${API_PREFIX}/properties`, authenticate, authorize('admin'), (req, res) => {
  try {
    const { name, address, owner_name, owner_phone } = req.body;
    
    if (!name) {
      return res.status(400).json({
        success: false,
        error: '缺少參數',
        message: '請提供物業名稱'
      });
    }
    
    const newProperty = {
      id: properties.length + 1,
      name,
      address: address || '',
      owner_name: owner_name || '',
      owner_phone: owner_phone || '',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    properties.push(newProperty);
    
    res.status(201).json({
      success: true,
      data: { property: newProperty },
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
app.get(`${API_PREFIX}/properties`, authenticate, (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        properties: properties,
        count: properties.length
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
app.get(`${API_PREFIX}/test`, (req, res) => {
  res.json({
    success: true,
    message: '🎉 API 測試成功！',
    data: {
      service: '台灣房東-越南租客系統',
      version: '無資料庫版本 1.0.0',
      status: 'active',
      time: new Date().toISOString(),
      stats: {
        users: users.length,
        properties: properties.length
      }
    }
  });
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
  console.log(`🚀 台灣房東系統 API (無資料庫版本) 啟動成功！`);
  console.log(`🌐 訪問: http://localhost:${port}`);
  console.log(`✅ 健康檢查: http://localhost:${port}/health`);
  console.log(`📚 API 文檔: http://localhost:${port}/api-docs`);
  console.log(`🔑 測試登入: username=admin, password=admin123`);
  console.log(`🔑 註冊端點: POST http://localhost:${port}${API_PREFIX}/auth/register`);
  console.log(`🔑 登入端點: POST http://localhost:${port}${API_PREFIX}/auth/login`);
  console.log(`\n📝 環境變數:`);
  console.log(`   JWT_SECRET: ${JWT_SECRET ? '已設置' : '未設置（使用默認值）'}`);
  console.log(`   PORT: ${port}`);
});