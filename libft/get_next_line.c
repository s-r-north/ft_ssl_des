/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/04/15 02:41:37 by snorth            #+#    #+#             */
/*   Updated: 2017/04/15 02:41:39 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	read_the_line(const int fd, size_t len, char **line, char **s)
{
	char	*tmp;
	size_t	count;
	int		buf;

	count = 0;
	tmp = ft_strnew(BUFF_SIZE);
	while ((buf = read(fd, tmp, BUFF_SIZE)) > 0)
	{
		count += buf;
		if (!(*line = (char*)ft_realloc((void*)(*line), count + 1 + len)))
			return (-1);
		ft_strncat(*line, tmp, buf);
		if (ft_strchr(tmp, 10))
			break ;
	}
	ft_memdel((void**)(&tmp));
	if ((buf == -1) || (buf == 0 && !(*line)))
		return (buf == -1 ? -1 : 0);
	if (ft_strchr(*line, 10))
	{
		*s = ft_strdup(ft_strchr(*line, 10) + 1);
		*(ft_strchr(*line, 10)) = 0;
	}
	return (1);
}

int			get_next_line(const int fd, char **line)
{
	static char	*s[MAX_FD];
	size_t		len;

	if (fd < 0 || fd >= MAX_FD || !(line))
		return (-1);
	if (*line)
		*line = 0;
	len = 0;
	if (s[fd] != NULL && ft_strlen(s[fd]) > 0)
	{
		len = !(ft_strchr(s[fd], 10)) ? ft_strlen(s[fd]) : ft_strchr(s[fd],
			10) + 1 - s[fd];
		*line = ft_strnew(len);
		ft_memccpy(*line, s[fd], 10, ft_strlen(s[fd]));
		if (ft_strchr(*line, 10))
		{
			*(ft_strchr(*line, 10)) = 0;
			ft_memmove(s[fd], ft_strchr(s[fd], 10) + 1, ft_strlen(s[fd]));
			return (1);
		}
		ft_strdel(&s[fd]);
	}
	return (read_the_line(fd, len, line, &s[fd]));
}
