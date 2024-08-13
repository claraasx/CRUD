const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

mongoose.connect('mongodb://localhost:27017/user_management', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' } // 'user' or 'admin'
});

const User = mongoose.model('User', userSchema);

// Middleware para autenticação
const auth = (role) => (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).send('Access Denied');

    try {
        const verified = jwt.verify(token, 'SECRET_KEY');
        req.user = verified;

        if (role && req.user.role !== role) {
            return res.status(403).send('Permission Denied');
        }

        next();
    } catch (err) {
        res.status(400).send('Invalid Token');
    }
};

// Cadastro de Usuário
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.json({ message: 'Usuário registrado com sucesso!' });
    } catch (err) {
        res.status(400).json({ message: 'Erro ao registrar usuário' });
    }
});

// Login de Usuário
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ message: 'Credenciais inválidas' });
    }

    const token = jwt.sign({ _id: user._id, role: user.role }, 'SECRET_KEY');
    res.json({ token });
});

// CRUD de Usuário

// Criar novo usuário (Apenas Admin)
app.post('/api/users', auth('admin'), async (req, res) => {
    const { username, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const newUser = new User({ username, password: hashedPassword, role });
        await newUser.save();
        res.json({ message: 'Usuário criado com sucesso!' });
    } catch (err) {
        res.status(400).json({ message: 'Erro ao criar usuário' });
    }
});

// Ler todos os usuários (Apenas Admin)
app.get('/api/users', auth('admin'), async (req, res) => {
    const users = await User.find().select('-password');
    res.json(users);
});

// Atualizar usuário (Apenas Admin)
app.put('/api/users/:id', auth('admin'), async (req, res) => {
    const { username, role } = req.body;

    try {
        const updatedUser = await User.findByIdAndUpdate(req.params.id, { username, role }, { new: true });
        res.json({ message: 'Usuário atualizado com sucesso!', updatedUser });
    } catch (err) {
        res.status(400).json({ message: 'Erro ao atualizar usuário' });
    }
});

// Excluir usuário (Apenas Admin)
app.delete('/api/users/:id', auth('admin'), async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'Usuário excluído com sucesso!' });
    } catch (err) {
        res.status(400).json({ message: 'Erro ao excluir usuário' });
    }
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
