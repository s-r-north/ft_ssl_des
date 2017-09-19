/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/02/28 21:42:16 by snorth            #+#    #+#             */
/*   Updated: 2017/03/03 17:08:49 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memchr(const void *s, int c, size_t n)
{
	unsigned char	*str;
	unsigned char	q;
	size_t			i;

	str = (unsigned char*)s;
	q = (unsigned char)c;
	i = -1;
	while (++i < n)
	{
		if (str[i] == q)
			return ((void*)&s[i]);
	}
	return (NULL);
}
