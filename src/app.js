const express = require('express');
const { engine } = require('express-handlebars');
const myconnection = require('express-myconnection');
const mysql = require('mysql');
const session = require('express-session');
const bodyParser = require('body-parser');
const app = express();
const loginRoutes = require('./routes/login');


// app.set('port', 4000);

app.set('views', __dirname + '/views');
app.engine('.hbs', engine({
  extname: '.hbs',
}));
app.set('view engine', 'hbs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const port = process.env.PORT || 4000;

app.use(myconnection(mysql, {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port: parseInt(process.env.DB_PORT), // convertir a número
  database: process.env.DB_NAME
}, 'single'));


app.use(session({
  secret: 'secret',
  resave: true,
  saveUninitialized: true
}));

// Rutas
app.use('/', loginRoutes);

// Página principal protegida
app.get('/', (req, res) => {
  if (req.session.loggedin == true) {
    res.render('home', { name: req.session.name });
  } else {
    res.redirect('/login');
  }
});



/********************************** */
// ---------------- FAVORITOS EN SESIÓN ----------------

// Mostrar favoritos
app.get('/favoritos', (req, res) => {
  if (!req.session.loggedin) return res.redirect('/login');
  res.render('favoritos', { 
    name: req.session.name,
    favoritos: req.session.favoritos || []
  });
});

// Agregar favorito
app.post('/addFavorito', (req, res) => {
  if (!req.session.favoritos) req.session.favoritos = [];

  const video = req.body;
  const exists = req.session.favoritos.some(v => v.videoId === video.videoId);
  
  if (!exists) req.session.favoritos.push(video);

  res.json({ success: true, favoritos: req.session.favoritos });
});

// Quitar favorito
app.post('/removeFavorito', (req, res) => {
  const { videoId } = req.body;
  req.session.favoritos = (req.session.favoritos || []).filter(v => v.videoId !== videoId);
  res.json({ success: true, favoritos: req.session.favoritos });
});




const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});