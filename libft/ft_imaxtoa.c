/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_imaxtoa.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/02/27 11:47:49 by snorth            #+#    #+#             */
/*   Updated: 2017/09/27 12:22:44 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_imaxtoa(intmax_t n)
{
	intmax_t	nb;
	size_t		len;
	int			sign;
	char		*ret;

	len = n < 0 ? 2 : 1;
	nb = n;
	while ((nb /= 10))
		len++;
	if (!(ret = ft_strnew(len)))
		return (NULL);
	if (n == 0)
		ret[0] = '0';
	sign = n < 0 ? -1 : 1;
	while (n)
	{
		ret[--len] = '0' + ((n % 10) * sign);
		n /= 10;
	}
	if (sign == -1)
		ret[--len] = '-';
	return (ret);
}

char	*ft_umaxtoa_base(uintmax_t n, size_t base)
{
	uintmax_t	nb;
	size_t		len;
	char		*ret;

	if (base < 2 || base > 36)
		return (NULL);
	len = 1;
	nb = n;
	while (nb /= base)
		len++;
	if (!(ret = ft_strnew(len)))
		return (NULL);
	if (n == 0)
		ret[0] = '0';
	while (n)
	{
		ret[--len] = ((n % base) + (n % base <= 9 ? '0' : ('a' - 10)));
		n /= base;
	}
	return (ret);
}
