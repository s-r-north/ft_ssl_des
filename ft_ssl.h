#ifndef FT_SSL_H
# define FT_SSL_H

# include "./libft/libft.h"

typedef struct	s_ssl
{
	int			fdin;
	int			fdout;
	char		*in;
	int			len;
	size_t		key;
	int			decrypt;
}				t_ssl;

char	b64set[64] = 
		{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };

void	set_struct(t_ssl *ssl);
int		error_func(char *s, int usage);

int		base_64(int ac, char **av);
int		read_func_base64(t_ssl *ssl);
void	base_64_encrypt(t_ssl *ssl);
void	base_64_decrypt(t_ssl *ssl);

#endif