app.post('/login', async (req, res) => {
    const { email, password } = req.body
    if (!email || !password) return res.status(400).json({error: 'faltan campos'});

    const user = user.get(email)
    if (!user) return res.status(401).json({ error: 'Credenciales invalidas'});

    const ok = await bcry.compare(password, user.passwordHash);
    if (! ok) return res.status(401).json({ error: 'credencial invalida'});
    
    const sid = createSession(user.id);

    res.cookie(SESSION_COOKIE_NAME, sid, {
        httpOnly: true,
        sameSite: 'strict',
        maxAge: SESSION_TTL_MS,
    })

    const token = createJwt(user);

    return res.json({ token });
})
