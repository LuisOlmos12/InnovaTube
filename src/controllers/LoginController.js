const bcrypt = require('bcrypt');
const axios = require('axios');

// Página de inicio de sesión
function login(req, res) {
  if (req.session.loggedin != true) {
    res.render('login/index');
  } else {
    res.redirect('/');
  }
}

// Autenticación
function auth(req, res) {
  const data = req.body;

  req.getConnection((err, conn) => {
    conn.query('SELECT * FROM users WHERE email = ?', [data.email], (err, userdata) => {
      if (userdata.length > 0) {
        userdata.forEach(element => {
          bcrypt.compare(data.password, element.password, (err, isMatch) => {
            if (!isMatch) {
              res.render('login/index', { error: 'Error: Contraseña incorrecta' });
            } else {
              req.session.loggedin = true;
              req.session.name = element.fullname;
              res.redirect('/');
            }
          });
        });
      } else {
        res.render('login/index', { error: 'Error: El usuario no existe' });
      }
    });
  });
}

// Página de registro
function register(req, res) {
  if (req.session.loggedin != true) {
    res.render('login/register');
  } else {
    res.redirect('/');
  }
}

// Guardar usuario en la BD
async function storeUser(req, res) {
  const data = req.body;

  // ✅ Verificar reCAPTCHA con Google
  const secretKey = '6LdSugcsAAAAABp5X8OKpTa5DQqqZL39r36CrztZ';
  const captcha = req.body['g-recaptcha-response'];

  if (!captcha) {
    return res.render('login/register', { error: 'Por favor, completa el reCAPTCHA.' });
  }

  try {
    const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captcha}`;
    const response = await axios.post(verifyUrl);

    if (!response.data.success) {
      return res.render('login/register', { error: 'Error en la verificación del reCAPTCHA.' });
    }

    // ✅ Validar que no exista el correo o usuario
    req.getConnection((err, conn) => {
      conn.query(
        'SELECT * FROM users WHERE email = ? OR username = ?',
        [data.email, data.username],
        (err, userdata) => {
          if (userdata.length > 0) {
            res.render('login/register', { error: 'El correo o nombre de usuario ya existen.' });
          } else {
            // ✅ Encriptar contraseña
            bcrypt.hash(data.password, 12).then(hash => {
              const newUser = {
                fullname: data.fullname,
                username: data.username,
                email: data.email,
                password: hash
              };

              conn.query('INSERT INTO users SET ?', [newUser], (err, rows) => {
                if (err) throw err;
                req.session.loggedin = true;
                req.session.name = data.fullname;
                res.redirect('/');
              });
            });
          }
        }
      );
    });
  } catch (err) {
    console.error(err);
    res.render('login/register', { error: 'Error al registrar el usuario.' });
  }
}

// Cerrar sesión
function logout(req, res) {
  if (req.session.loggedin == true) {
    req.session.destroy();
  }
  res.redirect('/login');
}

module.exports = {
  login,
  register,
  storeUser,
  auth,
  logout,
};
