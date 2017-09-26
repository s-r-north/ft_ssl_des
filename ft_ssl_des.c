#include "ft_ssl.h"

void	pc2(t_key *key)
{
	size_t i;

	key->cd = ((uint64_t)key->pc1c << 28) | key->pc1d;
	i = -1;
	key->k = 0;
	while (++i < 48)
	{
		key->k |= (1 & (key->cd >> g_pc2[i])) << (47 - i);
		// printf("%#.6x\t%u  %u\n", key->k, 1 & (key->k >> (47 - i)), 1 & (key->cd >> g_pc2[i]));
	}
	key->cd = 0;
	// printf("c: %x\td: %x\tkey inside: %llx", key->pc1c, key->pc1d, key->k);
}

void	permuted_choice(t_ssl *ssl)
{
	uint8_t	sh;
	size_t	i;

	i = -1;
	while (++i < 28)
		ssl->key[0].pc1c |= ((1 & (ssl->pass >> g_pc1[i])) << (27 - i));
	while (++i < 56)
		ssl->key[0].pc1d |= ((1 & (ssl->pass >> g_pc1[i])) << (55 - i));
	i = 0;
	while (++i < 17)
	{
		sh = 3 & (ssl->key[i - 1].pc1c >> (28 - g_shift[i]));
		ssl->key[i].pc1c = ssl->key[i - 1].pc1c << g_shift[i];
		ssl->key[i].pc1c |= sh;
		sh = 3 & (ssl->key[i - 1].pc1d >> (28 - g_shift[i]));
		ssl->key[i].pc1d = ssl->key[i - 1].pc1d << g_shift[i];
		ssl->key[i].pc1d |= sh;
		// ssl->key[i].pc1c = ((3 & (SHIFT(x) | 1)) & (ssl->key[i - 1].pc1c >> (28 - SHIFT(x))))
		// 		| (ssl->key[i - 1].pc1c << SHIFT(x));
		// ssl->key[i].pc1d = ((3 & (SHIFT(x) | 1)) & (ssl->key[i - 1].pc1d >> (28 - SHIFT(x))))
		// 		| (ssl->key[i - 1].pc1d << SHIFT(x));
		pc2(&(ssl->key[i]));
		// if (ssl->key[i].pc1c != cd_test[i][0])
		// 	printf("cx ");
		// if (ssl->key[i].pc1d != cd_test[i][1])
		// 	printf("dx ");
		// printf("\n");
		// if (ssl->key[i].k != key_test[i - 1])
		// 	printf("%zu: key: %llx\ttest key: %llx\n", i, ssl->key[i].k, key_test[i - 1]);
	}
	i = -1;
	while (++i < 17)
	{
		ssl->key[i].pc1c = 0;
		ssl->key[i].pc1d = 0;
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

	e.e = 0;
	e.sbx = 0;
	i = -1;
	while(++i < 48)
	{
		e.e |= (1 & (r >> g_ebit[i])) << (47 - i);
		printf("%#.12llx\t%u\t%u\t%u\t%zu\n", e.e, 1 & (e.e >> (47 - i)), 1 & (r >> g_ebit[i]), g_ebit[i], 47 - i);
	}
	if (e.e != 0b011110100001010101010101011110100001010101010101)
		printf("exp bad: %#.12llx\t%#.12llx\n", e.e, 0b011110100001010101010101011110100001010101010101);
	e.e ^= key->k;
	i = -1;
	while (++i < 8)
	{
		e.col = (0xf & (e.e >> (1 + 6 * i)));
		e.row = ((1 & (e.e >> (5 + 6 * i))) << 1) | (1 & (e.e >> (6 * i)));
		e.sbx |= (0xf & g_des_sbox[i][e.row][e.col]) << (4 * (7 - i));
	}
	out = 0;
	i = -1;
	while (++i < 32)
		out |= ((1 & e.sbx >> g_p_out[i])) << (31 - i);
	return (out);
}

void	des_encrypt(t_ssl *ssl)
{
	uint32_t	l[17];
	uint32_t	r[17];
	uint64_t	rl16;
	size_t i;

	i = -1;
	l[0] = 0;
	r[0] = 0;
	while (++i < 32)
		l[0] |= ((1 & (ssl->m >> g_ip[i])) << (31 - i));
	i--;
	while (++i < 64)
		r[0] |= ((1 & (ssl->m >> g_ip[i])) << (63 - i));
	// if (l[0] != 0b11001100000000001100110011111111)
	// 	printf("left ip bad\n");
	// if (r[0] != 0b11110000101010101111000010101010)
	// 	printf("right ip bad: %#x\t%#x\n", r[0], 0b11110000101010101111000010101010);
	i = 0;
	while (++i < 17)
	{
		l[i] = r[i - 1];
		r[i] = (l[i - 1]) ^ (des_feistel(r[i - 1], &(ssl->key[i])));
		if (i == 1 && r[1] != 0b11101111010010100110010101000100)
			printf("feistel bad: %#.8x\t%#.8x\n", r[1], 0b11101111010010100110010101000100);
	}
	rl16 = ((uint64_t)r[16] << 32) | l[16];
	i = -1;
	while (++i < 64)
		ssl->chain |= ((1 & (rl16 >> g_fp[i])) << (63 - i));
	if (ssl->chain != 0x85e813540f0ab405)
	{
		printf("Bad Shit\n");
		exit(-1);
	}
// 	i = -1;
// 	while (++i < 8)
// 		out[i] = 0xff & (ssl->chain >> (8 * (7 - i)));
}

int		main()
{
	t_ssl	ssl;

	ssl.fdin = 0;
	ssl.fdout = 1;
	ssl.cbc = 0;
	ssl.m = 0x0123456789abcdef;
	ssl.pass = 0x133457799bbcdff1;
	permuted_choice(&ssl);
	des_encrypt(&ssl);

}

// void	des_encrypt_in(t_ssl *ssl)
// {
// 	size_t i;
// 	char *out;

// 	i = 0;
// 	out = ft_strnew(ssl->len);
// 	ssl->cbc = 0; // put this in init later
// 	while (i < ssl->len)
// 	{
// 		des_message(ssl, i);
// 		des_encrypt(ssl, out + i);
// 		i += 8;
// 	}
// 	write(ssl->fdout, out, ssl->len);
// 	ft_strdel(&(ssl->in));
// 	ft_strdel(&out);
// }

// int		main(int ac, char **av)
// {
// 	t_ssl	ssl;

// 	ssl.in = NULL;
// 	ssl.fdin = 0;
// 	ssl.fdout = 1;
// 	if ((ssl.len = read_func_des(&ssl)) == -1)
// 		return (-1);
// 	ssl.pass = key_interpret(av[1]);
// 	permuted_choice(&ssl);
// 	if (ssl.decrypt)
// 		return (0); // decrypt function here
// 	else
// 		des_encrypt_in(&ssl);
// }

	// srand(0);
	// for (int i = -1; i < 16; ++i)
	// 	ssl.key[i].pc2 = rand();
	// for (int j = -1; j < 16; ++j)
	// 	printf("%#zx\t", ssl.key[j].pc2);