/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa_base.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/03/08 13:45:00 by snorth            #+#    #+#             */
/*   Updated: 2017/04/16 23:41:15 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void	ft_swap(char *a, char *b)
{
	char	tmp;

	tmp = *a;
	*a = *b;
	*b = tmp;
}

char		*ft_itoa_base(int n, int base)
{
	char	*store;
	size_t	len;
	size_t	i;
	int		sign;

	len = ft_numsize(n, base);
	if (!len || !(store = ft_strnew(len)))
		return (NULL);
	i = -1;
	if (n == 0)
		store[++i] = 48;
	sign = n < 0 ? -1 : 1;
	while (n != 0)
	{
		store[++i] = ((sign * (n % base)) + (n % base < 9 ? 48 : 87));
		n /= base;
	}
	store[++i] = sign == -1 ? '-' : 0;
	store[i == len - 1 ? i : i + 1] = 0;
	i = -1;
	while (++i < len / 2)
		ft_swap(&store[i], &store[len - i - 1]);
	return (store);
}
