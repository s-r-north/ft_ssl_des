#include "ft_ssl.h"

void	pc2(t_key *key)
{
	unsigned long	pc : 56;
	int i;

	pc = key->pc1c;
	pc = (pc << 28) | key->pc1d;
	i = -1;
	while (++i < 48)
		key->k = (key->k << 1) | (1 & (pc >> g_pc2[i]));
}

void	permuted_choice(t_ssl *ssl)
{
	unsigned int x;
	unsigned int n;
	int i;

	n = 7;
	while (n != 36)
	{
		ssl->key[0]->pc1c = (ssl->key[0]->pc1c << 1) | ((ssl->pass >> n) & 1);
		n += n > 55 ? -57 : 8;
	}
	n = 1;
	while (n != 4)
	{
		ssl->key[0]->pc1d = (ssl->key[0]->pc1d << 1) | ((ssl->pass >> n) & 1);
		n += n > 55 ? -55 : 8;
	}
	x = 0b0111111011111100;
	i = 0;
	while (++i < 17)
	{
		ssl->key[i]->pc1c = (shift(x) & (ssl->key[i - 1]->pc1c >> (28 - shift(x)))) | (ssl->key[i - 1]->pc1c << shift(x));
		ssl->key[i]->pc1d = (shift(x) & (ssl->key[i - 1]->pc1d >> (28 - shift(x)))) | (ssl->key[i - 1]->pc1d << shift(x));
		pc2(&(ssl->key[i]));
		x >>= 1;
	}
}

size_t	key_interpret(char *s)
{
	size_t	pass;

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
	return (rd == -1 ? rd : len);
}

int		main(int ac, char **av)
{
	t_ssl	ssl;

	ssl.in = NULL;
	ssl.fdin = 0;
	if ((ssl.len = read_func_des(&ssl)) == -1)
		return (-1);
	ssl.pass = key_interpret(av[1]);
	permuted_choice(&ssl);
}

	// srand(0);
	// for (int i = -1; i < 16; ++i)
	// 	ssl.key[i].pc2 = rand();
	// for (int j = -1; j < 16; ++j)
	// 	printf("%#zx\t", ssl.key[j].pc2);