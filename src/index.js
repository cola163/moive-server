//导入相关模块
const express = require("express");
const app = express();
const mongoose = require("mongoose")
const cors = require("cors")
const path = require("path");
const fs = require("fs");
const md5 = require("md5");
const bodyParser = require("body-parser");
const jsonwebtoken = require("jsonwebtoken");

//读取secret
const secret = fs.readFileSync(path.join(__dirname, "../", ".env"), "utf-8")

//mongoose的使用(1连接数据库2、产生schema对象3、产生模型4、调用具体方法)
mongoose.connect("mongodb://127.0.0.1:27017/maizuo", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});
//2、产生schema对象
const UserSchema = new mongoose.Schema({
    userId: {
        type: Number,
        required: true,
    },
    mobile: {
        type: String,
        required: true,
        //支持数据的修饰方法：get和set
        //get:获取数据的时候的数据处理方法
        //set:写入数据的时候数据的处理方法
        get:(val)=>{
            //val是指从数据库中提取出的原始数据
            //return返回处理好的值
            return val.replace(/(\d{3})\d{4}(\d{4})$/,"$1****$2")
        }
    },
    password: {
        type: String,
        required: true,
    },
    headIcon: String,
    gender: Number,
});
//3、产生模型
//第三参数为可选参数，表示model操作的表/集合名。如果不写第三额参数，
//则默认为第一参数小写的复数形式
const Model = mongoose.model("User", UserSchema, "users");




//中间件的使用
//解析表单数据
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
//解决跨域
app.use(cors())
//密码加密中间件
const passwdCrypt = (req, res, next) => {
    //明文密码字段为password
    //加盐加密或加料加密
    const passwd = md5(req.body.password + md5(req.body.password).substr(9, 17));
    // 将加密的密码挂载到req的body上(覆盖原密码)
    req.body.password = passwd
    //继续
    next()

}
//使用局部
// app.use(passwdCrypt)

//用户登录
app.post("/api/v1/user/login", passwdCrypt, (req, res) => {
    // 获取手机号与加密之后的密码
    let data = req.body
    //去数据库中去查询是否存在对应的记录
    //需要注意 mongoose提供的方法都是异步的
    Model.findOne(data).then(ret => {
        //findOne 查不到返回为null 查到就返回对应的数据（建议）
        //find 查不到返回空数组 进行判断恒为真
        if (ret) {
            //查到了，签发令牌
            //语法：jsonwebtoken.sign(载荷对象，secret)
            let _token = jsonwebtoken.sign({
                userId: ret.userId
            }, secret)
            res.send({
                error: 0,
                msg: "登陆成功！",
                _token,
                // _token:ret.mobile + " " + _token
            })
        } else {
            //没查到
            res.send({
                error: 1,
                msg: "手机号或密码错误"
            })
        }

    })
})

//获取用户信息
app.get("/api/v1/user/getUserInfo", (req, res) => {
    // 1. 认证token（在认证的过程中，如果认证失败，程序会抛异常）
    try {
        let tokenStr = req.headers["authorization"];
        let arr = tokenStr.split(" ");
        // 最后一个元素即token
        let token = arr[arr.length - 1];
        // 开始验证令牌
        // 语法：jsonwebtoken.verify(令牌字符串,secret)
        // 验证成功返回载荷，验证失败抛异常
        const ret = jsonwebtoken.verify(token, secret);
        // （可选）验证是否过期【约定过期时间2小时，7200s】
        if (Date.now() / 1000 - ret.iat > 7200) {
            // 过期了
            res.send({
                error: 3,
                msg: "token令牌已经过期。",
                _token: "",
            });
        } else {
            // 没过期
            // 判断是否马上要过期了，如果是自动给它生成新的token
            if (Date.now() / 1000 - ret.iat > 5400) {
                _token = jsonwebtoken.sign(
                    {
                        userId: ret.userId,
                    },
                    secret
                );
            }
            // 获取数据
            Model.findOne({ userId: ret.userId }).then((ret) => {
                // 2. 返回（失败或成功）
                if (ret) {
                    // 取到信息了，则返回
                    res.send({
                        error: 0,
                        msg: "用户信息获取成功！",
                        _token: token,
                        data: {
                            userId: ret.userId,
                            // mobile: ret.mobile.substr(0,3) +"****" +ret.mobile.substr(-4),
                            // mobile: ret.mobile.replace(/(\d{3})\d{4}(\d{4})$/,"$1****$2"),
                            mobile: ret.mobile,
                            headIcon: ret.headIcon,
                            gender: ret.gender,
                        },
                    });
                } else {
                    // 账号已经已经没了
                    res.send({
                        error: 4,
                        msg: "你号没了。",
                        _token: "",
                    });
                }
            });
        }
    } catch (error) {
        // 抛异常了
        res.status(500).send({
            error: 2,
            msg: "token令牌验证失败。",
        });
    }
});


//获取初始的数据库中的用户的密码加密结果（一次性接口）
app.post("/api/v1/user/passwdInit", passwdCrypt, (req, res) => {
    res.send("您的初始密码为123456，加密结果为：" + req.body.password)
})

app.listen(8000, () => {
    console.log(`Server is running at http://127.0.0.1:8000`)
});