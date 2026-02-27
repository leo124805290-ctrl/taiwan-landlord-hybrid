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

// 404 處理
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Not Found',
    message: `找不到路徑: ${req.path}`
  });
});

// 錯誤處理
app.use((err, req, res, next) => {
  console.error('伺服器錯誤:', err);
  res.status(500).json({
    success: false,
    error: 'Internal Server Error',
    message: '伺服器內部錯誤'
  });
});

// 啟動伺服器
app.listen(port, () => {
  console.log(`🚀 混合版本伺服器啟動！`);
  console.log(`🌐 訪問: http://localhost:${port}`);
  console.log(`✅ 健康檢查: http://localhost:${port}/health`);
  console.log(`📚 API 文檔: http://localhost:${port}/api-docs`);
  console.log(`🔑 註冊端點: POST http://localhost:${port}${API_PREFIX}/auth/register`);
  console.log(`🔑 登入端點: POST http://localhost:${port}${API_PREFIX}/auth/login`);
  console.log(`\n📝 必需環境變數:`);
  console.log(`   JWT_SECRET=你的密鑰`);
  console.log(`   DATABASE_URL=PostgreSQL連接字串`);
  console.log(`   (Zeabur 會自動提供 DATABASE_URL)`);
});