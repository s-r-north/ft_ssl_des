#ifndef FT_SSL_H
# define FT_SSL_H

# include "./libft/libft.h"
# define shift(a) ((1 & shift) + 1)

typedef struct	s_key
{
	size_t		pc1c : 28;
	size_t		pc1d : 28;
	size_t		k : 48;
}				t_key;

typedef struct	s_ssl
{
	int			decrypt;
	int			fdin;
	int			fdout;
	char		*in;
	int			len;
	size_t		pass;
	t_key		key[17];
	uint64_t	des_data;
}				t_ssl;

int				g_pc2[48] = 
	{	42, 39, 45, 32, 55, 51, 
		53, 28, 41, 50, 35, 46,
		33, 37, 44, 52, 30, 48,
		40, 49, 29, 36, 43, 54,
		15, 4, 25, 19, 9, 1,
		26, 16, 5, 11, 23, 8,
		12, 7, 17, 0, 22, 3,
		10, 14, 6, 20, 27, 24 };

const char		b64set[64] = 
		{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };

void	set_struct(t_ssl *ssl);
int		error_func(char *s, int usage);

int		base_64(int ac, char **av);
int		read_func_base64(t_ssl *ssl);
void	base_64_encrypt(t_ssl *ssl);
void	base_64_decrypt(t_ssl *ssl);

#endif