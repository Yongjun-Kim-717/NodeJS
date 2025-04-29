const express = require('express');
const path = require('path');
const http = require('http');
const mysql = require("mysql");
const cors = require("cors");
const crypto = require('crypto');
const { Server } = require("socket.io");
require("dotenv").config();
const jwt = require("jsonwebtoken");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// crypto 모듈로 비밀번호 암호화, 인자로 password와 콜백함수를 넘겨 비동기로 동작한다.
function getCryptoPassword(password, salt = null){
  return new Promise((resolve, reject) => {
    // flag : 로그인 시 1, 회원가입 시 0
    var flag = salt ? 1 : 0;

    // crypto 모듈 randomByte를 통해 salt값 생성
    crypto.randomBytes(64, (err, buf) => {
      if(err) return reject(err);

      // binary 데이터를 base64 인코딩 진행
      if(flag == 0)
        salt = buf.toString('base64');

      // password와 salt를 이용해 sha512 해쉬알고리즘 99999번 수행을바탕으로 64만큼의 길이를 가진 digest를 비동기로 생성
      crypto.pbkdf2(password, salt, 99999, 64, 'sha512', (err, key) => {
        if(err) return reject(err);

        if(flag == 0)
          resolve({ hashedPassword: key.toString('base64'), salt }); //성공 시 암호화 된 비밀번호와 salt값 반환
        else
          resolve({ hashedPassword: key.toString('base64') });
      })
    })
  })
}

// 토큰 검증 메서드
function authenticateToken(req, res, next){
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if(!token){
    return res.status(401).json({ message: "토큰이 없습니다." });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err){
      return res.status(403).json({ message: "유효하지 않은 토큰!" });
    }
    req.user = user;
    next();
  })
}


////////////////// mysql, 유니티 연결 /////////////////////

// 미들웨어 설정
app.use(express.json()); //JSON 파싱 (Post요청을 처리)
app.use(express.urlencoded({extend: true})); //URL-Encoded 파싱
app.use(cors()); // cors 허용

// MySQL 연결 설정
const db = mysql.createConnection({
  host: "spumstrikedb.c5s4k6wwqv38.ap-northeast-2.rds.amazonaws.com",
  user: "root",
  password: "godqhr01",
  database: "game_db"
});

db.connect(err => {
  if(err){
    console.error("MySQL 연결 실패", err);
    return;
  }
  console.log("MySQL 연결 성공!");
});

// 회원 가입 정보 저장
app.post("/api/signup", (req, res) => {
  console.log("클라이언트 요청 데이터:", req.body);

  const userID = req.body.userID || req.body.UserID;
  const userPW = req.body.userPassword || req.body.UserPassword;

  // 아이디, 비밀번호 null 값 방지
  if (!userID || !userPW) {
    return res.status(400).json({ message: "아이디와 비밀번호를 입력하세요!" });
  }

  // 아이디 검증 단계
  const sql_verify = "SELECT userID FROM userinfos WHERE userID = ?";

  db.query(sql_verify, [userID], (err, results) => {
    if(err)
    {
      console.error("데이터 로드 실패", err);
      return res.status(500).json({ message: "서버 오류 발생! "});
    }

    if (results.length > 0) {
      return res.status(400).json({ message: "이미 존재하는 ID 입니다!" });
    }

    // 해당 아이디 정보 없을 시 비밀번호 암호화 후 회원가입 진행
    getCryptoPassword(userPW).then(({ hashedPassword, salt }) => {
      const sql_insert = "INSERT INTO userinfos (userID, userPassword, salt) VALUES (?,?,?)";
  
      db.query(sql_insert, [userID, hashedPassword, salt], (err,result) => {
        if(err){
          console.error("데이터 저장 실패", err);
          return res.status(500).json({ message: "서버 오류 발생!"});
        }
        res.json({ message: "회원가입이 완료되었습니다!" });
      })
    }).catch((error) => {
      console.error("비밀번호 해싱 오류", error);
      res.status(500).json({ message: "비밀번호 암호화 중 오류 발생" });
    });
  });
});

// 로그인 api
// id, pw받아서 db에 정보조회 있으면 score 리턴
app.post("/api/login", (req,res) => {
  console.log("클라이언트 요청 데이터:", req.body);

  const userID = req.body.userID || req.body.UserID;
  const userPW = req.body.userPassword || req.body.UserPassword;

  // 아이디, 비밀번호 null 값 방지
  if (!userID || !userPW) {
    return res.status(400).json({ message: "아이디와 비밀번호를 입력하세요!" });
  }

  const sql_select = "SELECT userPassword, salt FROM userinfos WHERE userID = ?";
  db.query(sql_select, [userID], (err, results) =>{
    if(err) return res.status(500).json({ message: "서버 오류 발생!" });

    if(results.length === 0){
      return res.status(400).json({ message: "존재하지 않는 유저입니다." });
    }

    const { userPassword, salt } = results[0];

    // db에서 받아온 userPassword와 클라이언트에서 받아온 userPW를 암호화한 결과 값이 같다면 로그인
    getCryptoPassword(userPW, salt).then((hashedPW) => {
      if(hashedPW.hashedPassword !== userPassword) {
        console.log(hashedPW.hashedPassword);
        console.log(userPassword);
        return res.status(401).json({ message: "비밀번호가 일치하지 않습니다!" });
      }

      const jwtSecret = process.env.JWT_SECRET;
      // jws 토큰 생성(비밀 키를 그냥 일반 문자열로 할 시 토큰 무차별 생성이 가능 dotenv 패키지를 활용해 환경변수 env에 비밀키 생성하자                                                                                                                                                                                 )
      const token = jwt.sign({ userID }, jwtSecret, { expiresIn: "1h"});

      res.json({ message: "로그인 성공.", token })
    })
  })
})

// 점수 저장 api
app.post("/api/save_score", authenticateToken, (req,res) => {
  console.log("클라이언트 요청 데이터:", req.body);

  const userID = req.user.userID;
  const score = req.body.score;

  const sql_insert = "INSERT INTO scores (userID, score) VALUES (?, ?)";

  db.query(sql_insert, [userID, score], (err, results) => {
    if(err){
      return res.status(500).json({ message: "점수 저장 실패" });
    }

    res.json({message: "점수 저장 성공"});
  })
})

/////////////////// 프론트 연결 /////////////////////////

// React 앱의 build 폴더를 정적 파일로 제공
app.use(express.static(path.join(__dirname, '../my-app/build')));

// React의 index.html 파일 제공 (모든 라우트 처리)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../my-app/build', 'index.html'));
});

io.on('connection', (socket) => {
    console.log('a user connected');
})

const PORT = process.env.PORT || 5000;

server.listen(PORT,()=>console.log(`서버가 ${PORT} 에서 시작되었어요`))