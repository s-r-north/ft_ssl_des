/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/02/27 19:09:10 by snorth            #+#    #+#             */
/*   Updated: 2017/03/12 13:02:00 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t	ft_strlcat(char *dst, const char *src, size_t size)
{
	char		*d;
	const char	*s;
	size_t		len;
	size_t		dlen;

	d = dst;
	s = src;
	len = size;
	while (len-- != 0 && *d != 0)
		d++;
	dlen = d - dst;
	len = size - dlen;
	if (len == 0)
		return (dlen + ft_strlen(s));
	while (*s != 0)
	{
		if (len != 1)
		{
			*d++ = *s;
			len--;
		}
		s++;
	}
	*d = 0;
	return (dlen + (s - src));
}
