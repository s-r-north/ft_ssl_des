#include "ft_ssl.h"

void	pc2(t_key *key)
{
	uint64_t	cd;
	int i;

	cd = key->pc1c;
	cd = (cd << 28) | key->pc1d;
	i = -1;
	while (++i < 48)
		key->k = (key->k << 1) | (1 & (cd >> g_pc2[i]));
	key->pc1c = 0;
	key->pc1d = 0;
}

void	permuted_choice(t_ssl *ssl)
{
	uint32_t x;
	uint32_t n;
	int i;

	n = 7;
	while (n != 36)
	{
		ssl->key[0].pc1c = (ssl->key[0].pc1c << 1) | ((ssl->pass >> n) & 1);
		n += n > 55 ? -57 : 8;
	}
	n = 1;
	while (n != 4)
	{
		ssl->key[0].pc1d = (ssl->key[0].pc1d << 1) | ((ssl->pass >> n) & 1);
		n += n > 55 ? -55 : 8;
	}
	x = 0b0111111011111100;
	i = 0;
	while (++i < 17)
	{
		ssl->key[i].pc1c = (SHIFT(x) & (ssl->key[i - 1].pc1c >> (28 - SHIFT(x))))
				| (ssl->key[i - 1].pc1c << SHIFT(x));
		ssl->key[i].pc1d = (SHIFT(x) & (ssl->key[i - 1].pc1d >> (28 - SHIFT(x))))
				| (ssl->key[i - 1].pc1d << SHIFT(x));
		pc2(&(ssl->key[i]));
		x >>= 1;
	}
}

uint64_t	key_interpret(char *s)
{
	uint64_t	pass;

	pass = 0;
	while (*s)
	{
		pass <<= 4;
		if (*s >= '0' && *s <= '9')
			pass |= ((*s) - 48);
		else if (*s >= 'A' && *s <= 'F')
			pass |= ((*s) - 55);
		else if (*s >= 'a' && *s <= 'f')
			pass |= ((*s) - 87);
		s++;
	}
	return (pass);
}

int		read_func_des(t_ssl *ssl)
{
	int		rd;
	int		len;
	char	tmp[4097];

	len = 0;
	while ((rd = read(ssl->fdin, tmp, 4096)) > 0)
	{
		ssl->in = ft_realloc(ssl->in, rd + len + 1);
		ssl->in = (char*)ft_memcpy(ssl->in + len, tmp, rd);
		len += rd;
	}
	if (len % 8)
	{
		ssl->in = (char*)ft_realloc(ssl->in, len + 9 - (len % 8));
		ft_bzero(ssl->in + len, 9 - (len % 8));
		len += 8 - (len % 8);
	}
	ft_bzero(tmp, 4097);
	return (rd == -1 ? rd : len);
}

void	des_message(t_ssl *ssl, size_t cur)
{
	uint64_t	message;
	size_t		i;

	i = -1;
	message = 0;
	while (++i < 8)
		message |= ((uint64_t)ssl->in[cur + i] << (8 * (7 - i)));
	if (ssl->cbc)
		message ^= ssl->chain;
	ssl->m = message;
}

uint32_t	des_feistel(uint32_t r, t_key *key)
{
	t_exp		e;
	uint32_t	out;
	size_t		i;

	i = -1;
	while(++i < 48)
		e.e |= ((1 & r >> g_ebit[i]) << (47 - i));
	e.e ^= key->k;
	i = -1;
	while (++i < 8)
	{
		e.col = (0xf & (e.e >> (1 + 6 * i)));
		e.row = ((1 & (e.e >> (5 + 6 * i))) << 1) | (1 & (e.e >> (6 * i)));
		e.sbx |= (0xf & g_des_sbox[i][e.row][e.col]) << (4 * (7 - i));
	}
	i = -1;
	while (++i < 32)
		out |= ((1 & e.sbx >> g_p_out[i])) << (31 - i);
	return (out);
}

void	des_encrypt(t_ssl *ssl, char *out)
{
	uint32_t	l[17];
	uint32_t	r[17];
	uint64_t	rl16;
	size_t i;

	i = -1;
	while (++i < 32)
		l[0] |= ((1 & (ssl->m >> g_ip[i])) << (31 - i));
	while (++i < 64)
		r[0] |= ((1 & (ssl->m >> g_ip[i])) << (63 - i));
	i = 0;
	while (++i < 17)
	{
		l[i] = r[i - 1];
		r[i] = (l[i - 1]) ^ (des_feistel(r[i - 1], &(ssl->key[i])));
	}
	rl16 = ((uint64_t)r[16] << 32) | l[16];
	i = -1;
	while (++i < 64)
		ssl->chain |= ((1 & (rl16 >> g_fp[i])) << (63 - i));
	i = -1;
	while (++i < 8)
		out[i] = 0xff & (ssl->chain >> (8 * (7 - i)));
}

void	des_encrypt_in(t_ssl *ssl)
{
	size_t i;
	char *out;

	i = 0;
	out = ft_strnew(ssl->len);
	ssl->cbc = 0; // put this in init later
	while (i < ssl->len)
	{
		des_message(ssl, i);
		des_encrypt(ssl, out + i);
		i += 8;
	}
	write(ssl->fdout, out, ssl->len);
	ft_strdel(&(ssl->in));
	ft_strdel(&out);

}

int		main(int ac, char **av)
{
	t_ssl	ssl;

	ssl.in = NULL;
	ssl.fdin = 0;
	ssl.fdout = 1;
	if ((ssl.len = read_func_des(&ssl)) == -1)
		return (-1);
	ssl.pass = key_interpret(av[1]);
	permuted_choice(&ssl);
	if (ssl.decrypt)
		return (0); // decrypt function here
	else
		des_encrypt_in(&ssl);
}

	// srand(0);
	// for (int i = -1; i < 16; ++i)
	// 	ssl.key[i].pc2 = rand();
	// for (int j = -1; j < 16; ++j)
	// 	printf("%#zx\t", ssl.key[j].pc2);