/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memccpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/02/28 20:45:29 by snorth            #+#    #+#             */
/*   Updated: 2017/03/03 16:58:44 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memccpy(void *dst, const void *src, int c, size_t n)
{
	char	*ret;
	char	*source;
	size_t	i;

	ret = (char*)dst;
	source = (char*)src;
	i = -1;
	while (++i < n)
	{
		ret[i] = source[i];
		if (ret[i] == (char)c)
			return ((void*)&ret[i + 1]);
	}
	return (NULL);
}
