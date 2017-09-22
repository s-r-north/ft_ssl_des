#include "ft_ssl.h"

void	set_struct(t_ssl *ssl)
{
	ssl->fdin = 0;
	ssl->fdout = 1;
	ssl->decrypt = 0;
	ssl->in = NULL;
}

int		error_func(char *s, int usage)
{
	if (usage)
		write(1, "Usage\n: /*put proper usage stuff here*/", 6);
	else
		write(1, s, ft_strlen(s));
	return (-1);
}

void	base_64_encrypt(t_ssl *ssl)
{
	char	*out;
	char	*in;
	int		i;
	int		j;

	out = (char*)malloc((ssl->len * 4 / 3) + 1);
	in = ssl->in;
	i = 0;
	j = 0;
	while (i < ssl->len)
	{
		out[j++] = b64set[in[i] >> 2];
		out[j++] = b64set[077 & (in[i] << 4 | in[i + 1] >> 4)];
		out[j++] = (in[i + 1] || i + 3 < ssl->len) ?
				b64set[077 & (in[i + 1] << 2 | in[i + 2] >> 6)] : '=';
		out[j++] = (in[i + 2] || i + 3 < ssl->len) ?
				b64set[077 & in[i + 2]] : '=';
		i += 3;
	}
	write(ssl->fdout, out, ssl->len * 4 / 3);
	ft_strdel(&(ssl->in));
	ft_strdel(&out);
	if (ssl->fdout > 1)
		close(ssl->fdout);
}

void	base_64_decrypt(t_ssl *ssl)
{
	char	*out;
	char	*in;
	int		i;
	int		j;

	out = ft_strnew(ssl->len * 3 / 4);
	in = ssl->in;
	i = 0;
	j = 0;
	while (i < ssl->len)
	{
		out[j++] = (ft_strchr(b64set, in[i]) - b64set) << 2 |
				(ft_strchr(b64set, in[i + 1]) - b64set) >> 4;
		out[j++] = in[i + 2] == '=' ? 0 : ((ft_strchr(b64set, in[i + 1]) - b64set)
				<< 4) | ((ft_strchr(b64set, in[i + 2]) - b64set) >> 2);
		out[j++] = in[i + 3] == '=' ? 0 : ((ft_strchr(b64set, in[i + 2]) - b64set)
				<< 6) | ((ft_strchr(b64set, in[i + 3]) - b64set));
		i += 4;
	}
	write(ssl->fdout, out, ssl->len * 3 / 4);
	ft_strdel(&(ssl->in));
	ft_strdel(&out);
	if (ssl->fdout > 1)
		close(ssl->fdout);
}

int		read_func_base64(t_ssl *ssl)
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
	if (ssl->fdin)
		close(ssl->fdin);
	if (!ssl->decrypt && len % 3)
	{
		ssl->in = (char*)ft_realloc(ssl->in, len + 4 - (len % 3));
		ft_bzero(ssl->in + len, 4 - (len % 3));
		len += 3 - (len % 3);
	}
	if (ssl->decrypt && len % 4)
	{
		if (len % 4 == 1 && ssl->in[len - 1] == '\n')
		{
			ssl->in[len - 1] = 0;
			return (len - 1);
		}
		return (error_func("Bad Input\n", 0));
	}
	return (rd == -1 ? rd : len);
}

int		base_64(int ac, char **av)
{
	int		i;
	t_ssl	ssl;

	set_struct(&ssl);
	i = 1;
	while (++i < ac)
	{
		if (!ft_strcmp(av[i], "-i") && (i + 1) < ac)
		{
			if ((ssl.fdin = open(av[++i], O_RDONLY)) == -1)
				return (error_func("Open Error\n", 0));
		}
		else if (!ft_strcmp(av[i], "-o") && (i + 1) < ac)
		{
			if ((ssl.fdout = open(av[++i], O_WRONLY)) == -1)
				return (error_func("Open Error\n", 0));
		}
		else if (!ft_strcmp(av[i], "-d"))
			ssl.decrypt = 1;
		else if (ft_strcmp(av[i], "-e"))
			return (error_func(NULL, 1));
	}
	if ((ssl.len = read_func_base64(&ssl)) == -1)
		return (error_func("Read Error\n", 0));
	if (ssl.decrypt)
		base_64_decrypt(&ssl);
	else
		base_64_encrypt(&ssl);
	return (0);
}

int		main(int ac, char **av)
{
	if (ac < 3)
		return (error_func(NULL, 1));
	if (!ft_strcmp(av[1], "base64"))
		base_64(ac, av);
	else if (!ft_strcmp(av[1], "des"))
		return (1);//ft_des(ac, av);
	// write(1, "\n", 1);
	return (0);	
}